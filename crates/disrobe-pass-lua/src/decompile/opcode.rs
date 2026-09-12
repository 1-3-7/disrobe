use crate::reader::common::LuaDialect;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMode {
    Abc,
    Abx,
    AsBx,
    Ax,
    AsJ,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Move,
    LoadI,
    LoadF,
    LoadK,
    LoadKx,
    LoadBool,
    LoadFalse,
    LFalseSkip,
    LoadTrue,
    LoadNil,
    GetUpval,
    SetUpval,
    GetGlobal,
    SetGlobal,
    GetTabUp,
    GetTable,
    GetI,
    GetField,
    SetTabUp,
    SetTable,
    SetI,
    SetField,
    NewTable,
    Self_,
    AddI,
    AddK,
    SubK,
    MulK,
    ModK,
    PowK,
    DivK,
    IDivK,
    BAndK,
    BOrK,
    BXorK,
    ShrI,
    ShlI,
    Add,
    Sub,
    Mul,
    Mod,
    Pow,
    Div,
    IDiv,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
    MmBin,
    MmBinI,
    MmBinK,
    Unm,
    BNot,
    Not,
    Len,
    Concat,
    Close,
    Tbc,
    Jmp,
    Eq,
    Lt,
    Le,
    EqK,
    EqI,
    LtI,
    LeI,
    GtI,
    GeI,
    Test,
    TestSet,
    Call,
    TailCall,
    Return,
    Return0,
    Return1,
    ForLoop,
    ForPrep,
    TForPrep,
    TForCall,
    TForLoop,
    SetList,
    Closure,
    Vararg,
    VarargPrep,
    ExtraArg,
    Unknown,
}

impl Op {
    #[inline]
    #[must_use]
    pub const fn mode(self, dialect: LuaDialect) -> OpMode {
        match self {
            Self::LoadK | Self::LoadKx | Self::GetGlobal | Self::SetGlobal | Self::Closure => {
                OpMode::Abx
            }
            Self::LoadI | Self::LoadF => OpMode::AsBx,
            Self::Jmp => match dialect {
                LuaDialect::Lua54 => OpMode::AsJ,
                _ => OpMode::AsBx,
            },
            Self::ForLoop | Self::ForPrep | Self::TForPrep | Self::TForLoop => match dialect {
                LuaDialect::Lua54 => OpMode::Abx,
                _ => OpMode::AsBx,
            },
            Self::ExtraArg => OpMode::Ax,
            _ => OpMode::Abc,
        }
    }

    #[inline]
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Move => "MOVE",
            Self::LoadI => "LOADI",
            Self::LoadF => "LOADF",
            Self::LoadK => "LOADK",
            Self::LoadKx => "LOADKX",
            Self::LoadBool => "LOADBOOL",
            Self::LoadFalse => "LOADFALSE",
            Self::LFalseSkip => "LFALSESKIP",
            Self::LoadTrue => "LOADTRUE",
            Self::LoadNil => "LOADNIL",
            Self::GetUpval => "GETUPVAL",
            Self::SetUpval => "SETUPVAL",
            Self::GetGlobal => "GETGLOBAL",
            Self::SetGlobal => "SETGLOBAL",
            Self::GetTabUp => "GETTABUP",
            Self::GetTable => "GETTABLE",
            Self::GetI => "GETI",
            Self::GetField => "GETFIELD",
            Self::SetTabUp => "SETTABUP",
            Self::SetTable => "SETTABLE",
            Self::SetI => "SETI",
            Self::SetField => "SETFIELD",
            Self::NewTable => "NEWTABLE",
            Self::Self_ => "SELF",
            Self::AddI => "ADDI",
            Self::AddK => "ADDK",
            Self::SubK => "SUBK",
            Self::MulK => "MULK",
            Self::ModK => "MODK",
            Self::PowK => "POWK",
            Self::DivK => "DIVK",
            Self::IDivK => "IDIVK",
            Self::BAndK => "BANDK",
            Self::BOrK => "BORK",
            Self::BXorK => "BXORK",
            Self::ShrI => "SHRI",
            Self::ShlI => "SHLI",
            Self::Add => "ADD",
            Self::Sub => "SUB",
            Self::Mul => "MUL",
            Self::Mod => "MOD",
            Self::Pow => "POW",
            Self::Div => "DIV",
            Self::IDiv => "IDIV",
            Self::BAnd => "BAND",
            Self::BOr => "BOR",
            Self::BXor => "BXOR",
            Self::Shl => "SHL",
            Self::Shr => "SHR",
            Self::MmBin => "MMBIN",
            Self::MmBinI => "MMBINI",
            Self::MmBinK => "MMBINK",
            Self::Unm => "UNM",
            Self::BNot => "BNOT",
            Self::Not => "NOT",
            Self::Len => "LEN",
            Self::Concat => "CONCAT",
            Self::Close => "CLOSE",
            Self::Tbc => "TBC",
            Self::Jmp => "JMP",
            Self::Eq => "EQ",
            Self::Lt => "LT",
            Self::Le => "LE",
            Self::EqK => "EQK",
            Self::EqI => "EQI",
            Self::LtI => "LTI",
            Self::LeI => "LEI",
            Self::GtI => "GTI",
            Self::GeI => "GEI",
            Self::Test => "TEST",
            Self::TestSet => "TESTSET",
            Self::Call => "CALL",
            Self::TailCall => "TAILCALL",
            Self::Return => "RETURN",
            Self::Return0 => "RETURN0",
            Self::Return1 => "RETURN1",
            Self::ForLoop => "FORLOOP",
            Self::ForPrep => "FORPREP",
            Self::TForPrep => "TFORPREP",
            Self::TForCall => "TFORCALL",
            Self::TForLoop => "TFORLOOP",
            Self::SetList => "SETLIST",
            Self::Closure => "CLOSURE",
            Self::Vararg => "VARARG",
            Self::VarargPrep => "VARARGPREP",
            Self::ExtraArg => "EXTRAARG",
            Self::Unknown => "UNKNOWN",
        }
    }
}

const LUA51_OPS: [Op; 38] = [
    Op::Move,
    Op::LoadK,
    Op::LoadBool,
    Op::LoadNil,
    Op::GetUpval,
    Op::GetGlobal,
    Op::GetTable,
    Op::SetGlobal,
    Op::SetUpval,
    Op::SetTable,
    Op::NewTable,
    Op::Self_,
    Op::Add,
    Op::Sub,
    Op::Mul,
    Op::Div,
    Op::Mod,
    Op::Pow,
    Op::Unm,
    Op::Not,
    Op::Len,
    Op::Concat,
    Op::Jmp,
    Op::Eq,
    Op::Lt,
    Op::Le,
    Op::Test,
    Op::TestSet,
    Op::Call,
    Op::TailCall,
    Op::Return,
    Op::ForLoop,
    Op::ForPrep,
    Op::TForLoop,
    Op::SetList,
    Op::Close,
    Op::Closure,
    Op::Vararg,
];

const LUA52_OPS: [Op; 40] = [
    Op::Move,
    Op::LoadK,
    Op::LoadKx,
    Op::LoadBool,
    Op::LoadNil,
    Op::GetUpval,
    Op::GetTabUp,
    Op::GetTable,
    Op::SetTabUp,
    Op::SetUpval,
    Op::SetTable,
    Op::NewTable,
    Op::Self_,
    Op::Add,
    Op::Sub,
    Op::Mul,
    Op::Div,
    Op::Mod,
    Op::Pow,
    Op::Unm,
    Op::Not,
    Op::Len,
    Op::Concat,
    Op::Jmp,
    Op::Eq,
    Op::Lt,
    Op::Le,
    Op::Test,
    Op::TestSet,
    Op::Call,
    Op::TailCall,
    Op::Return,
    Op::ForLoop,
    Op::ForPrep,
    Op::TForCall,
    Op::TForLoop,
    Op::SetList,
    Op::Closure,
    Op::Vararg,
    Op::ExtraArg,
];

const LUA53_OPS: [Op; 47] = [
    Op::Move,
    Op::LoadK,
    Op::LoadKx,
    Op::LoadBool,
    Op::LoadNil,
    Op::GetUpval,
    Op::GetTabUp,
    Op::GetTable,
    Op::SetTabUp,
    Op::SetUpval,
    Op::SetTable,
    Op::NewTable,
    Op::Self_,
    Op::Add,
    Op::Sub,
    Op::Mul,
    Op::Mod,
    Op::Pow,
    Op::Div,
    Op::IDiv,
    Op::BAnd,
    Op::BOr,
    Op::BXor,
    Op::Shl,
    Op::Shr,
    Op::Unm,
    Op::BNot,
    Op::Not,
    Op::Len,
    Op::Concat,
    Op::Jmp,
    Op::Eq,
    Op::Lt,
    Op::Le,
    Op::Test,
    Op::TestSet,
    Op::Call,
    Op::TailCall,
    Op::Return,
    Op::ForLoop,
    Op::ForPrep,
    Op::TForCall,
    Op::TForLoop,
    Op::SetList,
    Op::Closure,
    Op::Vararg,
    Op::ExtraArg,
];

const LUA54_OPS: [Op; 83] = [
    Op::Move,
    Op::LoadI,
    Op::LoadF,
    Op::LoadK,
    Op::LoadKx,
    Op::LoadFalse,
    Op::LFalseSkip,
    Op::LoadTrue,
    Op::LoadNil,
    Op::GetUpval,
    Op::SetUpval,
    Op::GetTabUp,
    Op::GetTable,
    Op::GetI,
    Op::GetField,
    Op::SetTabUp,
    Op::SetTable,
    Op::SetI,
    Op::SetField,
    Op::NewTable,
    Op::Self_,
    Op::AddI,
    Op::AddK,
    Op::SubK,
    Op::MulK,
    Op::ModK,
    Op::PowK,
    Op::DivK,
    Op::IDivK,
    Op::BAndK,
    Op::BOrK,
    Op::BXorK,
    Op::ShrI,
    Op::ShlI,
    Op::Add,
    Op::Sub,
    Op::Mul,
    Op::Mod,
    Op::Pow,
    Op::Div,
    Op::IDiv,
    Op::BAnd,
    Op::BOr,
    Op::BXor,
    Op::Shl,
    Op::Shr,
    Op::MmBin,
    Op::MmBinI,
    Op::MmBinK,
    Op::Unm,
    Op::BNot,
    Op::Not,
    Op::Len,
    Op::Concat,
    Op::Close,
    Op::Tbc,
    Op::Jmp,
    Op::Eq,
    Op::Lt,
    Op::Le,
    Op::EqK,
    Op::EqI,
    Op::LtI,
    Op::LeI,
    Op::GtI,
    Op::GeI,
    Op::Test,
    Op::TestSet,
    Op::Call,
    Op::TailCall,
    Op::Return,
    Op::Return0,
    Op::Return1,
    Op::ForLoop,
    Op::ForPrep,
    Op::TForPrep,
    Op::TForCall,
    Op::TForLoop,
    Op::SetList,
    Op::Closure,
    Op::Vararg,
    Op::VarargPrep,
    Op::ExtraArg,
];

#[inline]
#[must_use]
pub fn decode_op(raw: u32, dialect: LuaDialect) -> Op {
    match dialect {
        LuaDialect::Lua54 => {
            let opcode: usize = (raw & 0x7F) as usize;
            LUA54_OPS.get(opcode).copied().unwrap_or(Op::Unknown)
        }
        LuaDialect::Lua53 => {
            let opcode: usize = (raw & 0x3F) as usize;
            LUA53_OPS.get(opcode).copied().unwrap_or(Op::Unknown)
        }
        LuaDialect::Lua52 => {
            let opcode: usize = (raw & 0x3F) as usize;
            LUA52_OPS.get(opcode).copied().unwrap_or(Op::Unknown)
        }
        LuaDialect::Lua51 | LuaDialect::GLua => {
            let opcode: usize = (raw & 0x3F) as usize;
            LUA51_OPS.get(opcode).copied().unwrap_or(Op::Unknown)
        }
        _ => {
            let opcode: usize = (raw & 0x3F) as usize;
            LUA51_OPS.get(opcode).copied().unwrap_or(Op::Unknown)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Decoded {
    pub op: Op,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub k: bool,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub sj: i32,
}

const SBX_BIAS_51: i32 = 0x1FFFF;
const SBX_BIAS_54: i32 = 0xFFFF;
const SJ_BIAS_54: i32 = 0xFF_FFFF;

#[inline]
#[must_use]
fn decode_54(raw: u32) -> Decoded {
    let op: Op = decode_op(raw, LuaDialect::Lua54);
    let a: u32 = (raw >> 7) & 0xFF;
    let k: bool = (raw >> 15) & 0x1 != 0;
    let b: u32 = (raw >> 16) & 0xFF;
    let c: u32 = (raw >> 24) & 0xFF;
    let bx: u32 = (raw >> 15) & 0x1FFFF;
    let sbx: i32 = bx as i32 - SBX_BIAS_54;
    let ax: u32 = (raw >> 7) & 0x1FF_FFFF;
    let sj: i32 = ax as i32 - SJ_BIAS_54;
    Decoded {
        op,
        a,
        b,
        c,
        k,
        bx,
        sbx,
        ax,
        sj,
    }
}

#[inline]
#[must_use]
fn decode_51(raw: u32, dialect: LuaDialect) -> Decoded {
    let op: Op = decode_op(raw, dialect);
    let a: u32 = (raw >> 6) & 0xFF;
    let c: u32 = (raw >> 14) & 0x1FF;
    let b: u32 = (raw >> 23) & 0x1FF;
    let bx: u32 = (raw >> 14) & 0x3FFFF;
    let sbx: i32 = bx as i32 - SBX_BIAS_51;
    let ax: u32 = (raw >> 6) & 0x3FF_FFFF;
    Decoded {
        op,
        a,
        b,
        c,
        k: false,
        bx,
        sbx,
        ax,
        sj: sbx,
    }
}

#[inline]
#[must_use]
pub fn decode(raw: u32, dialect: LuaDialect) -> Decoded {
    match dialect {
        LuaDialect::Lua54 => decode_54(raw),
        _ => decode_51(raw, dialect),
    }
}

pub const BITRK: u32 = 1 << 8;

#[inline]
#[must_use]
pub const fn is_k(field: u32) -> bool {
    field & BITRK != 0
}

#[inline]
#[must_use]
pub const fn rk_index(field: u32) -> u32 {
    field & !BITRK
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn decode_move_fields() {
        let raw: u32 = (3u32 << 6) | (5u32 << 23);
        let d: Decoded = decode(raw, LuaDialect::Lua51);
        assert_eq!(d.op, Op::Move);
        assert_eq!(d.a, 3);
        assert_eq!(d.b, 5);
    }

    #[test]
    fn decode_loadk_uses_bx() {
        let raw: u32 = 0x01u32 | (2u32 << 6) | (7u32 << 14);
        let d: Decoded = decode(raw, LuaDialect::Lua51);
        assert_eq!(d.op, Op::LoadK);
        assert_eq!(d.a, 2);
        assert_eq!(d.bx, 7);
    }

    #[test]
    fn jmp_sbx_is_signed() {
        let raw: u32 = 0x16u32 | ((SBX_BIAS_51 as u32 - 1) << 14);
        let d: Decoded = decode(raw, LuaDialect::Lua51);
        assert_eq!(d.op, Op::Jmp);
        assert_eq!(d.sbx, -1);
    }

    #[test]
    fn rk_classification() {
        assert!(is_k(BITRK | 5));
        assert!(!is_k(5));
        assert_eq!(rk_index(BITRK | 5), 5);
    }

    #[test]
    fn unknown_opcode_is_unknown() {
        let raw: u32 = 63;
        assert_eq!(decode_op(raw, LuaDialect::Lua51), Op::Unknown);
    }

    #[test]
    fn lua52_remaps_gettabup_and_drops_getglobal() {
        assert_eq!(decode_op(6, LuaDialect::Lua52), Op::GetTabUp);
        assert_eq!(decode_op(5, LuaDialect::Lua52), Op::GetUpval);
        assert_eq!(decode_op(39, LuaDialect::Lua52), Op::ExtraArg);
    }

    #[test]
    fn lua53_has_bitwise_ops() {
        assert_eq!(decode_op(20, LuaDialect::Lua53), Op::BAnd);
        assert_eq!(decode_op(19, LuaDialect::Lua53), Op::IDiv);
        assert_eq!(decode_op(26, LuaDialect::Lua53), Op::BNot);
    }

    #[test]
    fn lua54_seven_bit_opcode_and_layout() {
        let raw: u32 = 0x0000_0051;
        let d: Decoded = decode(raw, LuaDialect::Lua54);
        assert_eq!(d.op, Op::VarargPrep);
        let getup: u32 = 0x0000_000B;
        assert_eq!(decode(getup, LuaDialect::Lua54).op, Op::GetTabUp);
        let loadk: u32 = 0x00008083;
        let dk: Decoded = decode(loadk, LuaDialect::Lua54);
        assert_eq!(dk.op, Op::LoadK);
        assert_eq!(dk.a, 1);
        assert_eq!(dk.bx, 1);
        let call: u32 = 0x01020044;
        let dc: Decoded = decode(call, LuaDialect::Lua54);
        assert_eq!(dc.op, Op::Call);
        assert_eq!(dc.a, 0);
        assert_eq!(dc.b, 2);
        assert_eq!(dc.c, 1);
    }

    #[test]
    fn lua54_addi_and_return() {
        assert_eq!(decode_op(21, LuaDialect::Lua54), Op::AddI);
        assert_eq!(decode_op(70, LuaDialect::Lua54), Op::Return);
        assert_eq!(decode_op(71, LuaDialect::Lua54), Op::Return0);
        assert_eq!(decode_op(72, LuaDialect::Lua54), Op::Return1);
    }
}
