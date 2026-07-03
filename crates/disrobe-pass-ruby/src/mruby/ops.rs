use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperandFormat {
    Z,

    B,

    Bb,

    Bbb,

    Bs,

    Bss,

    S,

    W,
}

impl OperandFormat {
    #[inline]
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub const fn base_width(self) -> usize {
        match self {
            Self::Z => 0,
            Self::B => 1,
            Self::Bb => 2,
            Self::Bbb => 3,
            Self::Bs => 3,
            Self::Bss => 5,
            Self::S => 2,
            Self::W => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MrubyOp {
    Nop,
    Move,
    LoadL,
    LoadI,
    LoadINeg,
    LoadI16,
    LoadI32,
    LoadISmall(i8),
    LoadSym,
    LoadNil,
    LoadSelf,
    LoadT,
    LoadF,
    GetGv,
    SetGv,
    GetSv,
    SetSv,
    GetIv,
    SetIv,
    GetCv,
    SetCv,
    GetConst,
    SetConst,
    GetMCnst,
    SetMCnst,
    GetUpvar,
    SetUpvar,
    GetIdx,
    SetIdx,
    Jmp,
    JmpIf,
    JmpNot,
    JmpNil,
    JmpUw,
    Except,
    Rescue,
    RaiseIf,
    SSend,
    SSendB,
    Send,
    SendB,
    Call,
    Super,
    ArgAry,
    Enter,
    KeyP,
    KeyEnd,
    Karg,
    Return,
    ReturnBlk,
    Break,
    BlkPush,
    Add,
    AddI,
    Sub,
    SubI,
    Mul,
    Div,
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
    Array,
    Array2,
    AryCat,
    AryPush,
    ArySplat,
    Aref,
    Aset,
    Apost,
    Intern,
    Symbol,
    Strng,
    StrCat,
    Hash,
    HashAdd,
    HashCat,
    Lambda,
    Block,
    Method,
    RangeInc,
    RangeExc,
    OClass,
    Class,
    Module,
    Exec,
    Def,
    Alias,
    Undef,
    SClass,
    TClass,
    Debug,
    Err,
    Ext1,
    Ext2,
    Ext3,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MrubyOpcode {
    pub mnemonic: &'static str,
    pub format: OperandFormat,
    pub op: MrubyOp,
}

use OperandFormat::{B, Bb, Bbb, Bs, Bss, S, W, Z};

pub(crate) const OPS: &[MrubyOpcode] = &[
    MrubyOpcode {
        mnemonic: "NOP",
        format: Z,
        op: MrubyOp::Nop,
    },
    MrubyOpcode {
        mnemonic: "MOVE",
        format: Bb,
        op: MrubyOp::Move,
    },
    MrubyOpcode {
        mnemonic: "LOADL",
        format: Bb,
        op: MrubyOp::LoadL,
    },
    MrubyOpcode {
        mnemonic: "LOADI",
        format: Bb,
        op: MrubyOp::LoadI,
    },
    MrubyOpcode {
        mnemonic: "LOADINEG",
        format: Bb,
        op: MrubyOp::LoadINeg,
    },
    MrubyOpcode {
        mnemonic: "LOADI__1",
        format: B,
        op: MrubyOp::LoadISmall(-1),
    },
    MrubyOpcode {
        mnemonic: "LOADI_0",
        format: B,
        op: MrubyOp::LoadISmall(0),
    },
    MrubyOpcode {
        mnemonic: "LOADI_1",
        format: B,
        op: MrubyOp::LoadISmall(1),
    },
    MrubyOpcode {
        mnemonic: "LOADI_2",
        format: B,
        op: MrubyOp::LoadISmall(2),
    },
    MrubyOpcode {
        mnemonic: "LOADI_3",
        format: B,
        op: MrubyOp::LoadISmall(3),
    },
    MrubyOpcode {
        mnemonic: "LOADI_4",
        format: B,
        op: MrubyOp::LoadISmall(4),
    },
    MrubyOpcode {
        mnemonic: "LOADI_5",
        format: B,
        op: MrubyOp::LoadISmall(5),
    },
    MrubyOpcode {
        mnemonic: "LOADI_6",
        format: B,
        op: MrubyOp::LoadISmall(6),
    },
    MrubyOpcode {
        mnemonic: "LOADI_7",
        format: B,
        op: MrubyOp::LoadISmall(7),
    },
    MrubyOpcode {
        mnemonic: "LOADI16",
        format: Bs,
        op: MrubyOp::LoadI16,
    },
    MrubyOpcode {
        mnemonic: "LOADI32",
        format: Bss,
        op: MrubyOp::LoadI32,
    },
    MrubyOpcode {
        mnemonic: "LOADSYM",
        format: Bb,
        op: MrubyOp::LoadSym,
    },
    MrubyOpcode {
        mnemonic: "LOADNIL",
        format: B,
        op: MrubyOp::LoadNil,
    },
    MrubyOpcode {
        mnemonic: "LOADSELF",
        format: B,
        op: MrubyOp::LoadSelf,
    },
    MrubyOpcode {
        mnemonic: "LOADT",
        format: B,
        op: MrubyOp::LoadT,
    },
    MrubyOpcode {
        mnemonic: "LOADF",
        format: B,
        op: MrubyOp::LoadF,
    },
    MrubyOpcode {
        mnemonic: "GETGV",
        format: Bb,
        op: MrubyOp::GetGv,
    },
    MrubyOpcode {
        mnemonic: "SETGV",
        format: Bb,
        op: MrubyOp::SetGv,
    },
    MrubyOpcode {
        mnemonic: "GETSV",
        format: Bb,
        op: MrubyOp::GetSv,
    },
    MrubyOpcode {
        mnemonic: "SETSV",
        format: Bb,
        op: MrubyOp::SetSv,
    },
    MrubyOpcode {
        mnemonic: "GETIV",
        format: Bb,
        op: MrubyOp::GetIv,
    },
    MrubyOpcode {
        mnemonic: "SETIV",
        format: Bb,
        op: MrubyOp::SetIv,
    },
    MrubyOpcode {
        mnemonic: "GETCV",
        format: Bb,
        op: MrubyOp::GetCv,
    },
    MrubyOpcode {
        mnemonic: "SETCV",
        format: Bb,
        op: MrubyOp::SetCv,
    },
    MrubyOpcode {
        mnemonic: "GETCONST",
        format: Bb,
        op: MrubyOp::GetConst,
    },
    MrubyOpcode {
        mnemonic: "SETCONST",
        format: Bb,
        op: MrubyOp::SetConst,
    },
    MrubyOpcode {
        mnemonic: "GETMCNST",
        format: Bb,
        op: MrubyOp::GetMCnst,
    },
    MrubyOpcode {
        mnemonic: "SETMCNST",
        format: Bb,
        op: MrubyOp::SetMCnst,
    },
    MrubyOpcode {
        mnemonic: "GETUPVAR",
        format: Bbb,
        op: MrubyOp::GetUpvar,
    },
    MrubyOpcode {
        mnemonic: "SETUPVAR",
        format: Bbb,
        op: MrubyOp::SetUpvar,
    },
    MrubyOpcode {
        mnemonic: "GETIDX",
        format: B,
        op: MrubyOp::GetIdx,
    },
    MrubyOpcode {
        mnemonic: "SETIDX",
        format: B,
        op: MrubyOp::SetIdx,
    },
    MrubyOpcode {
        mnemonic: "JMP",
        format: S,
        op: MrubyOp::Jmp,
    },
    MrubyOpcode {
        mnemonic: "JMPIF",
        format: Bs,
        op: MrubyOp::JmpIf,
    },
    MrubyOpcode {
        mnemonic: "JMPNOT",
        format: Bs,
        op: MrubyOp::JmpNot,
    },
    MrubyOpcode {
        mnemonic: "JMPNIL",
        format: Bs,
        op: MrubyOp::JmpNil,
    },
    MrubyOpcode {
        mnemonic: "JMPUW",
        format: S,
        op: MrubyOp::JmpUw,
    },
    MrubyOpcode {
        mnemonic: "EXCEPT",
        format: B,
        op: MrubyOp::Except,
    },
    MrubyOpcode {
        mnemonic: "RESCUE",
        format: Bb,
        op: MrubyOp::Rescue,
    },
    MrubyOpcode {
        mnemonic: "RAISEIF",
        format: B,
        op: MrubyOp::RaiseIf,
    },
    MrubyOpcode {
        mnemonic: "SSEND",
        format: Bbb,
        op: MrubyOp::SSend,
    },
    MrubyOpcode {
        mnemonic: "SSENDB",
        format: Bbb,
        op: MrubyOp::SSendB,
    },
    MrubyOpcode {
        mnemonic: "SEND",
        format: Bbb,
        op: MrubyOp::Send,
    },
    MrubyOpcode {
        mnemonic: "SENDB",
        format: Bbb,
        op: MrubyOp::SendB,
    },
    MrubyOpcode {
        mnemonic: "CALL",
        format: Z,
        op: MrubyOp::Call,
    },
    MrubyOpcode {
        mnemonic: "SUPER",
        format: Bb,
        op: MrubyOp::Super,
    },
    MrubyOpcode {
        mnemonic: "ARGARY",
        format: Bs,
        op: MrubyOp::ArgAry,
    },
    MrubyOpcode {
        mnemonic: "ENTER",
        format: W,
        op: MrubyOp::Enter,
    },
    MrubyOpcode {
        mnemonic: "KEY_P",
        format: Bb,
        op: MrubyOp::KeyP,
    },
    MrubyOpcode {
        mnemonic: "KEYEND",
        format: Z,
        op: MrubyOp::KeyEnd,
    },
    MrubyOpcode {
        mnemonic: "KARG",
        format: Bb,
        op: MrubyOp::Karg,
    },
    MrubyOpcode {
        mnemonic: "RETURN",
        format: B,
        op: MrubyOp::Return,
    },
    MrubyOpcode {
        mnemonic: "RETURN_BLK",
        format: B,
        op: MrubyOp::ReturnBlk,
    },
    MrubyOpcode {
        mnemonic: "BREAK",
        format: B,
        op: MrubyOp::Break,
    },
    MrubyOpcode {
        mnemonic: "BLKPUSH",
        format: Bs,
        op: MrubyOp::BlkPush,
    },
    MrubyOpcode {
        mnemonic: "ADD",
        format: B,
        op: MrubyOp::Add,
    },
    MrubyOpcode {
        mnemonic: "ADDI",
        format: Bb,
        op: MrubyOp::AddI,
    },
    MrubyOpcode {
        mnemonic: "SUB",
        format: B,
        op: MrubyOp::Sub,
    },
    MrubyOpcode {
        mnemonic: "SUBI",
        format: Bb,
        op: MrubyOp::SubI,
    },
    MrubyOpcode {
        mnemonic: "MUL",
        format: B,
        op: MrubyOp::Mul,
    },
    MrubyOpcode {
        mnemonic: "DIV",
        format: B,
        op: MrubyOp::Div,
    },
    MrubyOpcode {
        mnemonic: "EQ",
        format: B,
        op: MrubyOp::Eq,
    },
    MrubyOpcode {
        mnemonic: "LT",
        format: B,
        op: MrubyOp::Lt,
    },
    MrubyOpcode {
        mnemonic: "LE",
        format: B,
        op: MrubyOp::Le,
    },
    MrubyOpcode {
        mnemonic: "GT",
        format: B,
        op: MrubyOp::Gt,
    },
    MrubyOpcode {
        mnemonic: "GE",
        format: B,
        op: MrubyOp::Ge,
    },
    MrubyOpcode {
        mnemonic: "ARRAY",
        format: Bb,
        op: MrubyOp::Array,
    },
    MrubyOpcode {
        mnemonic: "ARRAY2",
        format: Bbb,
        op: MrubyOp::Array2,
    },
    MrubyOpcode {
        mnemonic: "ARYCAT",
        format: B,
        op: MrubyOp::AryCat,
    },
    MrubyOpcode {
        mnemonic: "ARYPUSH",
        format: Bb,
        op: MrubyOp::AryPush,
    },
    MrubyOpcode {
        mnemonic: "ARYSPLAT",
        format: B,
        op: MrubyOp::ArySplat,
    },
    MrubyOpcode {
        mnemonic: "AREF",
        format: Bbb,
        op: MrubyOp::Aref,
    },
    MrubyOpcode {
        mnemonic: "ASET",
        format: Bbb,
        op: MrubyOp::Aset,
    },
    MrubyOpcode {
        mnemonic: "APOST",
        format: Bbb,
        op: MrubyOp::Apost,
    },
    MrubyOpcode {
        mnemonic: "INTERN",
        format: B,
        op: MrubyOp::Intern,
    },
    MrubyOpcode {
        mnemonic: "SYMBOL",
        format: Bb,
        op: MrubyOp::Symbol,
    },
    MrubyOpcode {
        mnemonic: "STRING",
        format: Bb,
        op: MrubyOp::Strng,
    },
    MrubyOpcode {
        mnemonic: "STRCAT",
        format: B,
        op: MrubyOp::StrCat,
    },
    MrubyOpcode {
        mnemonic: "HASH",
        format: Bb,
        op: MrubyOp::Hash,
    },
    MrubyOpcode {
        mnemonic: "HASHADD",
        format: Bb,
        op: MrubyOp::HashAdd,
    },
    MrubyOpcode {
        mnemonic: "HASHCAT",
        format: B,
        op: MrubyOp::HashCat,
    },
    MrubyOpcode {
        mnemonic: "LAMBDA",
        format: Bb,
        op: MrubyOp::Lambda,
    },
    MrubyOpcode {
        mnemonic: "BLOCK",
        format: Bb,
        op: MrubyOp::Block,
    },
    MrubyOpcode {
        mnemonic: "METHOD",
        format: Bb,
        op: MrubyOp::Method,
    },
    MrubyOpcode {
        mnemonic: "RANGE_INC",
        format: B,
        op: MrubyOp::RangeInc,
    },
    MrubyOpcode {
        mnemonic: "RANGE_EXC",
        format: B,
        op: MrubyOp::RangeExc,
    },
    MrubyOpcode {
        mnemonic: "OCLASS",
        format: B,
        op: MrubyOp::OClass,
    },
    MrubyOpcode {
        mnemonic: "CLASS",
        format: Bb,
        op: MrubyOp::Class,
    },
    MrubyOpcode {
        mnemonic: "MODULE",
        format: Bb,
        op: MrubyOp::Module,
    },
    MrubyOpcode {
        mnemonic: "EXEC",
        format: Bb,
        op: MrubyOp::Exec,
    },
    MrubyOpcode {
        mnemonic: "DEF",
        format: Bb,
        op: MrubyOp::Def,
    },
    MrubyOpcode {
        mnemonic: "ALIAS",
        format: Bb,
        op: MrubyOp::Alias,
    },
    MrubyOpcode {
        mnemonic: "UNDEF",
        format: B,
        op: MrubyOp::Undef,
    },
    MrubyOpcode {
        mnemonic: "SCLASS",
        format: B,
        op: MrubyOp::SClass,
    },
    MrubyOpcode {
        mnemonic: "TCLASS",
        format: B,
        op: MrubyOp::TClass,
    },
    MrubyOpcode {
        mnemonic: "DEBUG",
        format: Bbb,
        op: MrubyOp::Debug,
    },
    MrubyOpcode {
        mnemonic: "ERR",
        format: B,
        op: MrubyOp::Err,
    },
    MrubyOpcode {
        mnemonic: "EXT1",
        format: Z,
        op: MrubyOp::Ext1,
    },
    MrubyOpcode {
        mnemonic: "EXT2",
        format: Z,
        op: MrubyOp::Ext2,
    },
    MrubyOpcode {
        mnemonic: "EXT3",
        format: Z,
        op: MrubyOp::Ext3,
    },
    MrubyOpcode {
        mnemonic: "STOP",
        format: Z,
        op: MrubyOp::Stop,
    },
];

#[inline]
#[must_use]
pub(crate) fn lookup(op: u8) -> Option<&'static MrubyOpcode> {
    OPS.get(op as usize)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn opcode_numbering_matches_enum_order() {
        assert_eq!(OPS[0].mnemonic, "NOP");
        assert_eq!(OPS[1].mnemonic, "MOVE");
        assert_eq!(OPS[2].mnemonic, "LOADL");
        assert_eq!(OPS[3].mnemonic, "LOADI");
        assert_eq!(OPS[16].mnemonic, "LOADSYM");
        assert_eq!(OPS[OPS.len() - 1].mnemonic, "STOP");
    }

    #[test]
    fn send_is_bbb() {
        let send: &MrubyOpcode = lookup(47).expect("SEND present");
        assert_eq!(send.mnemonic, "SEND");
        assert_eq!(send.format, OperandFormat::Bbb);
        assert_eq!(send.format.base_width(), 3);
    }

    #[test]
    fn jmp_is_s_word() {
        let jmp: &MrubyOpcode = OPS.iter().find(|o| o.mnemonic == "JMP").expect("JMP");
        assert_eq!(jmp.format, OperandFormat::S);
        assert_eq!(jmp.format.base_width(), 2);
    }

    #[test]
    fn out_of_range_opcode_is_none() {
        assert!(lookup(0xFF).is_none());
    }
}
