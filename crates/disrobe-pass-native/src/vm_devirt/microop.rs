use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BinKind {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnKind {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CmpKind {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmOperand {
    None,
    Imm,
    RegIndex,
    StackSlot,
    BranchTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum MicroOp {
    PushImm,
    PushReg,
    PopReg,
    LoadMem,
    StoreMem,
    Binary { op: BinKind },
    Unary { op: UnKind },
    Compare { op: CmpKind },
    BranchTrue,
    BranchFalse,
    Jump,
    Call,
    Return,
    Nop,
    Unknown,
}

impl MicroOp {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::PushImm => "push.imm",
            Self::PushReg => "push.reg",
            Self::PopReg => "pop.reg",
            Self::LoadMem => "load",
            Self::StoreMem => "store",
            Self::Binary { op } => match op {
                BinKind::Add => "add",
                BinKind::Sub => "sub",
                BinKind::Mul => "mul",
                BinKind::Div => "div",
                BinKind::Rem => "rem",
                BinKind::And => "and",
                BinKind::Or => "or",
                BinKind::Xor => "xor",
                BinKind::Shl => "shl",
                BinKind::Shr => "shr",
                BinKind::Sar => "sar",
            },
            Self::Unary { op } => match op {
                UnKind::Neg => "neg",
                UnKind::Not => "not",
            },
            Self::Compare { op } => match op {
                CmpKind::Eq => "cmp.eq",
                CmpKind::Ne => "cmp.ne",
                CmpKind::Lt => "cmp.lt",
                CmpKind::Le => "cmp.le",
                CmpKind::Gt => "cmp.gt",
                CmpKind::Ge => "cmp.ge",
            },
            Self::BranchTrue => "br.true",
            Self::BranchFalse => "br.false",
            Self::Jump => "jmp",
            Self::Call => "call",
            Self::Return => "ret",
            Self::Nop => "nop",
            Self::Unknown => "??",
        }
    }

    #[must_use]
    pub const fn is_terminator(self) -> bool {
        matches!(
            self,
            Self::BranchTrue | Self::BranchFalse | Self::Jump | Self::Return
        )
    }

    #[must_use]
    pub const fn is_conditional_branch(self) -> bool {
        matches!(self, Self::BranchTrue | Self::BranchFalse)
    }
}

impl BinKind {
    #[must_use]
    pub fn apply(self, a: i64, b: i64) -> i64 {
        match self {
            Self::Add => a.wrapping_add(b),
            Self::Sub => a.wrapping_sub(b),
            Self::Mul => a.wrapping_mul(b),
            Self::Div => {
                if b == 0 {
                    0
                } else {
                    a.wrapping_div(b)
                }
            }
            Self::Rem => {
                if b == 0 {
                    0
                } else {
                    a.wrapping_rem(b)
                }
            }
            Self::And => a & b,
            Self::Or => a | b,
            Self::Xor => a ^ b,
            Self::Shl => a.wrapping_shl((b & 0x3F) as u32),
            Self::Shr => ((a as u64) >> ((b & 0x3F) as u32)) as i64,
            Self::Sar => a >> ((b & 0x3F) as u32),
        }
    }
}

impl UnKind {
    #[must_use]
    pub const fn apply(self, a: i64) -> i64 {
        match self {
            Self::Neg => a.wrapping_neg(),
            Self::Not => !a,
        }
    }
}

impl CmpKind {
    #[must_use]
    pub const fn apply(self, a: i64, b: i64) -> bool {
        match self {
            Self::Eq => a == b,
            Self::Ne => a != b,
            Self::Lt => a < b,
            Self::Le => a <= b,
            Self::Gt => a > b,
            Self::Ge => a >= b,
        }
    }
}
