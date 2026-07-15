use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
pub enum SourceLang {
    #[default]
    Unknown,
    NativeX86,
    NativeArm,
    Wasm,
    Jvm,
    Dalvik,
    Cil,
    Python,
    Lua,
    Avm2,
    Yarv,
    Beam,
}

impl SourceLang {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NativeX86 => "native-x86",
            Self::NativeArm => "native-arm",
            Self::Wasm => "wasm",
            Self::Jvm => "jvm",
            Self::Dalvik => "dalvik",
            Self::Cil => "cil",
            Self::Python => "python",
            Self::Lua => "lua",
            Self::Avm2 => "avm2",
            Self::Yarv => "yarv",
            Self::Beam => "beam",
        }
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
)]
#[rkyv(derive(Debug))]
pub struct SourceRef {
    pub lang: SourceLang,
    pub location: u64,
    pub label: String,
}

impl SourceRef {
    #[must_use]
    pub const fn new(lang: SourceLang, location: u64) -> Self {
        Self {
            lang,
            location,
            label: String::new(),
        }
    }

    #[must_use]
    pub fn labelled(lang: SourceLang, location: u64, label: impl Into<String>) -> Self {
        Self {
            lang,
            location,
            label: label.into(),
        }
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
pub enum BinaryOp {
    #[default]
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
    Rol,
    Ror,
    Not,
    Neg,
}

impl BinaryOp {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Div => "div",
            Self::Rem => "rem",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Shl => "shl",
            Self::Shr => "shr",
            Self::Rol => "rol",
            Self::Ror => "ror",
            Self::Not => "not",
            Self::Neg => "neg",
        }
    }

    #[must_use]
    pub const fn is_byte_arith_candidate(self) -> bool {
        matches!(
            self,
            Self::Add
                | Self::Sub
                | Self::And
                | Self::Or
                | Self::Xor
                | Self::Shl
                | Self::Shr
                | Self::Rol
                | Self::Ror
                | Self::Not
                | Self::Neg
        )
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
)]
#[rkyv(derive(Debug))]
pub struct CallOtherEffect {
    pub name: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub reads_memory: bool,
    pub writes_memory: bool,
    pub unknown_registers: bool,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
pub enum ValueOp {
    BoolAnd,
    BoolNegate,
    BoolOr,
    BoolXor,
    FloatAdd,
    FloatDiv,
    FloatEqual,
    FloatLess,
    FloatLessEqual,
    FloatMult,
    FloatSqrt,
    FloatSub,
    FloatToFloat,
    FloatTrunc,
    IntToFloat,
    #[default]
    IntAdd,
    IntAnd,
    IntCarry,
    IntDiv,
    IntEqual,
    IntLeft,
    IntLess,
    IntLessEqual,
    IntMult,
    IntNegate,
    IntNotEqual,
    IntOr,
    IntRem,
    IntRight,
    IntSignedBorrow,
    IntSignedCarry,
    IntSignedDiv,
    IntSignedLess,
    IntSignedLessEqual,
    IntSignedRem,
    IntSignedRight,
    IntSub,
    IntXor,
    IntSext,
    IntZext,
}

impl ValueOp {
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::BoolAnd => "BOOL_AND",
            Self::BoolNegate => "BOOL_NEGATE",
            Self::BoolOr => "BOOL_OR",
            Self::BoolXor => "BOOL_XOR",
            Self::FloatAdd => "FLOAT_ADD",
            Self::FloatDiv => "FLOAT_DIV",
            Self::FloatEqual => "FLOAT_EQUAL",
            Self::FloatLess => "FLOAT_LESS",
            Self::FloatLessEqual => "FLOAT_LESSEQUAL",
            Self::FloatMult => "FLOAT_MULT",
            Self::FloatSqrt => "FLOAT_SQRT",
            Self::FloatSub => "FLOAT_SUB",
            Self::FloatToFloat => "FLOAT_FLOAT2FLOAT",
            Self::FloatTrunc => "FLOAT_TRUNC",
            Self::IntToFloat => "FLOAT_INT2FLOAT",
            Self::IntAdd => "INT_ADD",
            Self::IntAnd => "INT_AND",
            Self::IntCarry => "INT_CARRY",
            Self::IntDiv => "INT_DIV",
            Self::IntEqual => "INT_EQUAL",
            Self::IntLeft => "INT_LEFT",
            Self::IntLess => "INT_LESS",
            Self::IntLessEqual => "INT_LESSEQUAL",
            Self::IntMult => "INT_MULT",
            Self::IntNegate => "INT_NEGATE",
            Self::IntNotEqual => "INT_NOTEQUAL",
            Self::IntOr => "INT_OR",
            Self::IntRem => "INT_REM",
            Self::IntRight => "INT_RIGHT",
            Self::IntSignedBorrow => "INT_SBORROW",
            Self::IntSignedCarry => "INT_SCARRY",
            Self::IntSignedDiv => "INT_SDIV",
            Self::IntSignedLess => "INT_SLESS",
            Self::IntSignedLessEqual => "INT_SLESSEQUAL",
            Self::IntSignedRem => "INT_SREM",
            Self::IntSignedRight => "INT_SRIGHT",
            Self::IntSub => "INT_SUB",
            Self::IntXor => "INT_XOR",
            Self::IntSext => "INT_SEXT",
            Self::IntZext => "INT_ZEXT",
        }
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
)]
#[rkyv(derive(Debug))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum NirOp {
    #[default]
    Nop,
    Const,
    BinOp {
        op: BinaryOp,
    },
    Load,
    Store,
    Call {
        target: Option<u64>,
    },
    IndirectCall,
    ExternCall {
        symbol: String,
    },
    Branch {
        target: Option<u64>,
    },
    CondBranch {
        target: Option<u64>,
    },
    Phi,
    Return,
    Interrupt,
    Unmodeled {
        opcode: u8,
        offset: u32,
    },
    RawLoad {
        addr: String,
        size: u32,
    },
    RawStore {
        addr: String,
        value: String,
        size: u32,
    },
    Subpiece {
        src: String,
        offset: u32,
        size: u32,
    },
    Deposit {
        cell: String,
        value: String,
        offset: u32,
        size: u32,
        cell_size: u32,
        zero_upper: bool,
    },
    CallOther {
        effect: CallOtherEffect,
    },
    Copy {
        src: String,
        size: u32,
    },
    Value {
        op: ValueOp,
        inputs: Vec<String>,
        input_sizes: Vec<u32>,
        size: u32,
    },
    Piece {
        high: String,
        low: String,
        high_size: u32,
        low_size: u32,
        size: u32,
    },
    NoReturnCall {
        target: Option<u64>,
    },
    TailCall {
        target: Option<u64>,
    },
}

impl NirOp {
    #[must_use]
    pub const fn class(&self) -> NirClass {
        match self {
            Self::Call { .. }
            | Self::NoReturnCall { .. }
            | Self::TailCall { .. }
            | Self::IndirectCall
            | Self::ExternCall { .. } => NirClass::Call,
            Self::Branch { .. } => NirClass::UnconditionalJump,
            Self::CondBranch { .. } => NirClass::ConditionalJump,
            Self::Return => NirClass::Return,
            Self::Nop
            | Self::Const
            | Self::BinOp { .. }
            | Self::Load
            | Self::Store
            | Self::Phi
            | Self::Interrupt
            | Self::Unmodeled { .. }
            | Self::RawLoad { .. }
            | Self::RawStore { .. }
            | Self::Subpiece { .. }
            | Self::Deposit { .. }
            | Self::CallOther { .. }
            | Self::Copy { .. }
            | Self::Value { .. }
            | Self::Piece { .. } => NirClass::Other,
        }
    }

    #[must_use]
    pub const fn is_unmodeled(&self) -> bool {
        matches!(self, Self::Unmodeled { .. })
    }

    #[must_use]
    pub const fn unmodeled_opcode(&self) -> Option<u8> {
        match self {
            Self::Unmodeled { opcode, .. } => Some(*opcode),
            _ => None,
        }
    }

    #[must_use]
    pub const fn direct_target(&self) -> Option<u64> {
        match self {
            Self::Call { target }
            | Self::NoReturnCall { target }
            | Self::TailCall { target }
            | Self::Branch { target }
            | Self::CondBranch { target } => *target,
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_terminal_call(&self) -> bool {
        matches!(self, Self::NoReturnCall { .. } | Self::TailCall { .. })
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
pub enum NirClass {
    Call,
    UnconditionalJump,
    ConditionalJump,
    Return,
    Other,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
)]
#[rkyv(derive(Debug))]
pub struct NirInstr {
    pub address: u64,
    pub op: NirOp,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub reads_memory: bool,
    pub writes_memory: bool,
    pub byte_width: bool,
    pub source: SourceRef,
}

impl NirInstr {
    #[must_use]
    pub const fn class(&self) -> NirClass {
        self.op.class()
    }

    #[must_use]
    pub const fn direct_target(&self) -> Option<u64> {
        self.op.direct_target()
    }

    #[must_use]
    pub const fn touches_memory(&self) -> bool {
        self.reads_memory || self.writes_memory
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    Function,
    Data,
    Label,
    Export,
    Import,
}

impl SymbolKind {
    #[must_use]
    pub const fn is_external(self) -> bool {
        matches!(self, Self::Import)
    }

    #[must_use]
    pub const fn is_callable(self) -> bool {
        matches!(self, Self::Function | Self::Export)
    }
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct NirSymbol {
    pub address: u64,
    pub name: String,
    pub kind: SymbolKind,
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct NirFunction {
    pub name: String,
    pub address: u64,
    pub end: u64,
    pub is_export: bool,
    pub instructions: Vec<NirInstr>,
    pub source: SourceRef,
}

impl NirFunction {
    #[must_use]
    pub const fn contains_address(&self, address: u64) -> bool {
        address >= self.address
            && (address < self.end || (self.end == u64::MAX && address == u64::MAX))
    }

    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct NirModule {
    pub source_hash: [u8; 32],
    pub lang: SourceLang,
    pub functions: Vec<NirFunction>,
    pub symbols: Vec<NirSymbol>,
}

impl NirModule {
    #[must_use]
    pub const fn new(source_hash: [u8; 32], lang: SourceLang) -> Self {
        Self {
            source_hash,
            lang,
            functions: Vec::new(),
            symbols: Vec::new(),
        }
    }

    #[must_use]
    pub fn function_by_name(&self, name: &str) -> Option<&NirFunction> {
        self.functions
            .iter()
            .find(|f: &&NirFunction| f.name == name)
    }

    #[must_use]
    pub fn symbol_address(&self, name: &str) -> Option<u64> {
        self.symbols
            .iter()
            .find(|s: &&NirSymbol| s.name == name)
            .map(|s: &NirSymbol| s.address)
    }

    #[must_use]
    pub fn symbol_at(&self, address: u64) -> Option<&NirSymbol> {
        self.symbols
            .iter()
            .find(|s: &&NirSymbol| s.address == address)
    }

    #[must_use]
    pub fn function_containing(&self, address: u64) -> Option<&NirFunction> {
        self.functions
            .iter()
            .find(|f: &&NirFunction| f.contains_address(address))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::codec::{decode_nir, encode_nir};

    fn instr(address: u64, op: NirOp, mnemonic: &str) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: Vec::new(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    #[test]
    fn op_class_maps_to_query_classes() {
        assert_eq!(NirOp::Call { target: Some(1) }.class(), NirClass::Call);
        assert_eq!(NirOp::IndirectCall.class(), NirClass::Call);
        assert_eq!(
            NirOp::ExternCall {
                symbol: "send".to_owned()
            }
            .class(),
            NirClass::Call
        );
        assert_eq!(
            NirOp::Branch { target: Some(2) }.class(),
            NirClass::UnconditionalJump
        );
        assert_eq!(
            NirOp::CondBranch { target: Some(2) }.class(),
            NirClass::ConditionalJump
        );
        assert_eq!(NirOp::Return.class(), NirClass::Return);
        assert_eq!(NirOp::Nop.class(), NirClass::Other);
    }

    #[test]
    fn native_memory_alias_and_effect_ops_are_additive_other_ops() {
        let effect: CallOtherEffect = CallOtherEffect {
            name: "x86_probe_reads_writes_mem_v1".to_owned(),
            reads: vec!["rax".to_owned()],
            writes: vec!["rdx".to_owned()],
            reads_memory: true,
            writes_memory: true,
            unknown_registers: false,
        };
        let operations: Vec<NirOp> = vec![
            NirOp::RawLoad {
                addr: "rax".to_owned(),
                size: 4,
            },
            NirOp::RawStore {
                addr: "rax".to_owned(),
                value: "rdx".to_owned(),
                size: 4,
            },
            NirOp::Subpiece {
                src: "rax".to_owned(),
                offset: 1,
                size: 1,
            },
            NirOp::Deposit {
                cell: "rax".to_owned(),
                value: "t0".to_owned(),
                offset: 0,
                size: 4,
                cell_size: 8,
                zero_upper: true,
            },
            NirOp::CallOther { effect },
        ];
        assert!(operations.iter().all(|operation: &NirOp| {
            operation.class() == NirClass::Other && !operation.is_unmodeled()
        }));
    }

    #[test]
    fn native_ops_round_trip_through_rkyv() {
        let function: NirFunction = NirFunction {
            name: "native".to_owned(),
            address: 0x1000,
            end: 0x1001,
            is_export: false,
            instructions: vec![instr(
                0x1000,
                NirOp::RawLoad {
                    addr: "rax".to_owned(),
                    size: 8,
                },
                "LOAD",
            )],
            source: SourceRef::new(SourceLang::NativeX86, 0x1000),
        };
        let module: NirModule = NirModule {
            source_hash: [0x5a; 32],
            lang: SourceLang::NativeX86,
            functions: vec![function],
            symbols: Vec::new(),
        };
        let bytes: Vec<u8> = encode_nir(&module).expect("encode native nir");
        let decoded: NirModule = decode_nir(&bytes).expect("decode native nir");
        assert_eq!(decoded, module);
    }

    #[test]
    fn direct_target_only_for_direct_control_flow() {
        assert_eq!(NirOp::Call { target: Some(9) }.direct_target(), Some(9));
        assert_eq!(NirOp::IndirectCall.direct_target(), None);
        assert_eq!(NirOp::Return.direct_target(), None);
    }

    #[test]
    fn module_round_trips_through_rkyv() {
        let module: NirModule = NirModule {
            source_hash: [0x33; 32],
            lang: SourceLang::NativeX86,
            functions: vec![NirFunction {
                name: "main".to_owned(),
                address: 0x10,
                end: 0x20,
                is_export: true,
                instructions: vec![
                    instr(0x10, NirOp::Call { target: Some(0x40) }, "call"),
                    instr(0x15, NirOp::Return, "ret"),
                ],
                source: SourceRef::new(SourceLang::NativeX86, 0x10),
            }],
            symbols: vec![NirSymbol {
                address: 0x40,
                name: "helper".to_owned(),
                kind: SymbolKind::Function,
            }],
        };
        let bytes: Vec<u8> = encode_nir(&module).expect("encode");
        let decoded: NirModule = decode_nir(&bytes).expect("decode");
        assert_eq!(module, decoded);
        assert_eq!(
            decoded.function_by_name("main").map(|f| f.address),
            Some(0x10)
        );
        assert_eq!(decoded.symbol_address("helper"), Some(0x40));
        assert_eq!(
            decoded.function_containing(0x15).map(|f| f.name.as_str()),
            Some("main")
        );
    }

    #[test]
    fn symbol_kind_classification() {
        assert!(SymbolKind::Import.is_external());
        assert!(!SymbolKind::Function.is_external());
        assert!(SymbolKind::Export.is_callable());
        assert!(SymbolKind::Function.is_callable());
        assert!(!SymbolKind::Data.is_callable());
    }

    #[test]
    fn contains_address_keeps_max_address_when_end_is_saturated() {
        let function: NirFunction = NirFunction {
            name: "max_addr".to_owned(),
            address: u64::MAX,
            end: u64::MAX,
            is_export: false,
            instructions: vec![instr(u64::MAX, NirOp::Return, "ret")],
            source: SourceRef::new(SourceLang::NativeX86, u64::MAX),
        };
        assert!(function.contains_address(u64::MAX));
    }
}
