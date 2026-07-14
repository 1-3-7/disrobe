use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Space {
    Constant,
    Ram,
    Register,
    Unique,
}

impl Display for Space {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let name: &str = match self {
            Self::Constant => "const",
            Self::Ram => "ram",
            Self::Register => "register",
            Self::Unique => "unique",
        };
        formatter.write_str(name)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Varnode {
    pub offset: u64,
    pub size_bytes: u32,
    pub space: Space,
}

impl Display for Varnode {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:0x{:x}:{}",
            self.space, self.offset, self.size_bytes
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PcodeOp {
    BoolAnd {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    BoolNegate {
        output: Varnode,
        input: Varnode,
    },
    BoolOr {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    BoolXor {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    Branch {
        target: Varnode,
    },
    BranchIndirect {
        target: Varnode,
    },
    CBranch {
        target: Varnode,
        condition: Varnode,
    },
    Call {
        target: Varnode,
    },
    CallIndirect {
        target: Varnode,
    },
    CallOther {
        name: String,
        output: Option<Varnode>,
        inputs: Vec<Varnode>,
    },
    Copy {
        output: Varnode,
        input: Varnode,
    },
    IntAdd {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntAnd {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntCarry {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntDiv {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntEqual {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntLeft {
        output: Varnode,
        input: Varnode,
        amount: Varnode,
    },
    IntLess {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntLessEqual {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntMult {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntNegate {
        output: Varnode,
        input: Varnode,
    },
    IntNotEqual {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntOr {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntRem {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntRight {
        output: Varnode,
        input: Varnode,
        amount: Varnode,
    },
    IntSignedBorrow {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedCarry {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedDiv {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedLess {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedLessEqual {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedRem {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSignedRight {
        output: Varnode,
        input: Varnode,
        amount: Varnode,
    },
    IntSub {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntXor {
        output: Varnode,
        left: Varnode,
        right: Varnode,
    },
    IntSext {
        output: Varnode,
        input: Varnode,
    },
    IntZext {
        output: Varnode,
        input: Varnode,
    },
    Load {
        output: Varnode,
        space: Space,
        pointer: Varnode,
    },
    Piece {
        output: Varnode,
        high: Varnode,
        low: Varnode,
    },
    Return {
        target: Option<Varnode>,
    },
    Store {
        space: Space,
        pointer: Varnode,
        value: Varnode,
    },
    Subpiece {
        output: Varnode,
        input: Varnode,
        byte_offset: Varnode,
    },
}

impl PcodeOp {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::BoolAnd { .. } => "BOOL_AND",
            Self::BoolNegate { .. } => "BOOL_NEGATE",
            Self::BoolOr { .. } => "BOOL_OR",
            Self::BoolXor { .. } => "BOOL_XOR",
            Self::Branch { .. } => "BRANCH",
            Self::BranchIndirect { .. } => "BRANCHIND",
            Self::CBranch { .. } => "CBRANCH",
            Self::Call { .. } => "CALL",
            Self::CallIndirect { .. } => "CALLIND",
            Self::CallOther { .. } => "CALLOTHER",
            Self::Copy { .. } => "COPY",
            Self::IntAdd { .. } => "INT_ADD",
            Self::IntAnd { .. } => "INT_AND",
            Self::IntCarry { .. } => "INT_CARRY",
            Self::IntDiv { .. } => "INT_DIV",
            Self::IntEqual { .. } => "INT_EQUAL",
            Self::IntLeft { .. } => "INT_LEFT",
            Self::IntLess { .. } => "INT_LESS",
            Self::IntLessEqual { .. } => "INT_LESSEQUAL",
            Self::IntMult { .. } => "INT_MULT",
            Self::IntNegate { .. } => "INT_NEGATE",
            Self::IntNotEqual { .. } => "INT_NOTEQUAL",
            Self::IntOr { .. } => "INT_OR",
            Self::IntRem { .. } => "INT_REM",
            Self::IntRight { .. } => "INT_RIGHT",
            Self::IntSignedBorrow { .. } => "INT_SBORROW",
            Self::IntSignedCarry { .. } => "INT_SCARRY",
            Self::IntSignedDiv { .. } => "INT_SDIV",
            Self::IntSignedLess { .. } => "INT_SLESS",
            Self::IntSignedLessEqual { .. } => "INT_SLESSEQUAL",
            Self::IntSignedRem { .. } => "INT_SREM",
            Self::IntSignedRight { .. } => "INT_SRIGHT",
            Self::IntSub { .. } => "INT_SUB",
            Self::IntXor { .. } => "INT_XOR",
            Self::IntSext { .. } => "INT_SEXT",
            Self::IntZext { .. } => "INT_ZEXT",
            Self::Load { .. } => "LOAD",
            Self::Piece { .. } => "PIECE",
            Self::Return { .. } => "RETURN",
            Self::Store { .. } => "STORE",
            Self::Subpiece { .. } => "SUBPIECE",
        }
    }

    pub const fn is_callother(&self) -> bool {
        matches!(self, Self::CallOther { .. })
    }
}

impl Display for PcodeOp {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallOther {
                name,
                output,
                inputs,
            } => write!(formatter, "CALLOTHER {name} {output:?} {inputs:?}"),
            _ => formatter.write_str(self.name()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStatus {
    Ambiguous,
    CallOther,
    NoMatch,
    SpecError,
    Supported,
    Truncated,
    Unsupported,
}

impl DecodeStatus {
    pub const fn matched_constructor(self) -> bool {
        matches!(self, Self::Supported | Self::CallOther | Self::Unsupported)
    }

    pub const fn supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcodeInstr {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub length: usize,
    pub mnemonic: String,
    pub ops: Vec<PcodeOp>,
    pub operands: String,
    pub status: DecodeStatus,
}
