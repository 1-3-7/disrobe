use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

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
    NativeMips,
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
            Self::NativeMips => "native-mips",
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

const MAX_SOURCE_UNITS: usize = 1_048_576;
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_NIR_ELEMENTS: usize = MAX_SOURCE_UNITS;
const MAX_NIR_STRING_BYTES: usize = MAX_SOURCE_BYTES;
const MAX_NIR_RETAINED_BYTES: usize = 256 * 1024 * 1024;
const MAX_NIR_WORK: usize = 8 * MAX_NIR_ELEMENTS;

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[rkyv(derive(Debug))]
pub struct FileSourceOffset {
    offset: u64,
    file_length: u64,
}

#[derive(Deserialize)]
struct FileSourceOffsetWire {
    offset: u64,
    file_length: u64,
}

impl<'de> Deserialize<'de> for FileSourceOffset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire: FileSourceOffsetWire = FileSourceOffsetWire::deserialize(deserializer)?;
        Self::new(wire.offset, wire.file_length).map_err(de::Error::custom)
    }
}

impl FileSourceOffset {
    pub const fn new(offset: u64, file_length: u64) -> Result<Self, NirProvenanceError> {
        if offset > file_length {
            return Err(NirProvenanceError::FileOffset {
                offset,
                file_length,
            });
        }
        Ok(Self {
            offset,
            file_length,
        })
    }

    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn file_length(self) -> u64 {
        self.file_length
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
#[non_exhaustive]
pub enum SourceOffsetUnavailable {
    Decompressed,
    Decrypted,
    Synthesized,
    ContainerMember,
    Unknown,
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
#[non_exhaustive]
pub enum SourceOffset {
    File(FileSourceOffset),
    MemoryImage(u64),
    Unavailable(SourceOffsetUnavailable),
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SourceBytes {
    Original(Vec<u8>),
    Synthesized,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SourceBytesVariant {
    Original,
    Synthesized,
}

struct BoundedBytesSeed {
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedBytesSeed {
    type Value = Vec<u8>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedBytesVisitor { limit: self.limit })
    }
}

struct BoundedBytesVisitor {
    limit: usize,
}

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded source byte sequence")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let hinted: usize = sequence.size_hint().unwrap_or(0);
        if hinted > self.limit {
            return Err(de::Error::custom(NirProvenanceError::ByteLimit {
                limit: MAX_SOURCE_BYTES,
            }));
        }
        let mut bytes: Vec<u8> = Vec::new();
        bytes.try_reserve_exact(hinted).map_err(de::Error::custom)?;
        while let Some(byte) = sequence.next_element::<u8>()? {
            if bytes.len() == self.limit {
                return Err(de::Error::custom(NirProvenanceError::ByteLimit {
                    limit: MAX_SOURCE_BYTES,
                }));
            }
            if bytes.len() == bytes.capacity() {
                bytes.try_reserve_exact(1).map_err(de::Error::custom)?;
            }
            bytes.push(byte);
        }
        Ok(bytes)
    }
}

struct SourceBytesSeed {
    limit: usize,
}

impl<'de> DeserializeSeed<'de> for SourceBytesSeed {
    type Value = SourceBytes;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_enum(
            "SourceBytes",
            &["original", "synthesized"],
            SourceBytesVisitor { limit: self.limit },
        )
    }
}

struct SourceBytesVisitor {
    limit: usize,
}

impl<'de> Visitor<'de> for SourceBytesVisitor {
    type Value = SourceBytes;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a source byte variant")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let (variant, value): (SourceBytesVariant, A::Variant) = data.variant()?;
        match variant {
            SourceBytesVariant::Original => value
                .newtype_variant_seed(BoundedBytesSeed { limit: self.limit })
                .map(SourceBytes::Original),
            SourceBytesVariant::Synthesized => {
                value.unit_variant()?;
                Ok(SourceBytes::Synthesized)
            }
        }
    }
}

impl<'de> Deserialize<'de> for SourceBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SourceBytesSeed {
            limit: MAX_SOURCE_BYTES,
        }
        .deserialize(deserializer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SourceBytesRef<'a> {
    Original(&'a [u8]),
    Synthesized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceUnitRef<'a> {
    function_index: u32,
    instruction_start: u32,
    instruction_end: u32,
    bytes: SourceBytesRef<'a>,
    offset: SourceOffset,
}

impl<'a> SourceUnitRef<'a> {
    pub fn new(
        function_index: u32,
        instructions: std::ops::Range<u32>,
        bytes: SourceBytesRef<'a>,
        offset: SourceOffset,
    ) -> Result<Self, NirProvenanceError> {
        let original_byte_length: Option<usize> = match bytes {
            SourceBytesRef::Original(value) => Some(value.len()),
            SourceBytesRef::Synthesized => None,
        };
        validate_source_unit(instructions.clone(), original_byte_length, offset)?;
        Ok(Self {
            function_index,
            instruction_start: instructions.start,
            instruction_end: instructions.end,
            bytes,
            offset,
        })
    }

    #[must_use]
    pub const fn original_bytes(self) -> Option<&'a [u8]> {
        match self.bytes {
            SourceBytesRef::Original(value) => Some(value),
            SourceBytesRef::Synthesized => None,
        }
    }

    pub fn into_owned(self) -> Result<SourceUnit, NirProvenanceError> {
        self.into_owned_with_limit(MAX_SOURCE_BYTES)
    }

    fn into_owned_with_limit(self, byte_limit: usize) -> Result<SourceUnit, NirProvenanceError> {
        let bytes: SourceBytes = match self.bytes {
            SourceBytesRef::Original(value) => {
                if value.len() > byte_limit {
                    return Err(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    });
                }
                let mut owned: Vec<u8> = Vec::new();
                owned.try_reserve_exact(value.len()).map_err(|_error| {
                    NirProvenanceError::Allocation {
                        requested: value.len(),
                    }
                })?;
                owned.extend_from_slice(value);
                SourceBytes::Original(owned)
            }
            SourceBytesRef::Synthesized => SourceBytes::Synthesized,
        };
        SourceUnit::new(
            self.function_index,
            self.instruction_start..self.instruction_end,
            bytes,
            self.offset,
        )
    }
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct SourceUnit {
    function_index: u32,
    instruction_start: u32,
    instruction_end: u32,
    bytes: SourceBytes,
    offset: SourceOffset,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum SourceUnitField {
    FunctionIndex,
    InstructionStart,
    InstructionEnd,
    Bytes,
    Offset,
}

struct SourceUnitSeed {
    byte_limit: usize,
}

impl<'de> DeserializeSeed<'de> for SourceUnitSeed {
    type Value = SourceUnit;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "SourceUnit",
            &[
                "function_index",
                "instruction_start",
                "instruction_end",
                "bytes",
                "offset",
            ],
            SourceUnitVisitor {
                byte_limit: self.byte_limit,
            },
        )
    }
}

struct SourceUnitVisitor {
    byte_limit: usize,
}

impl<'de> Visitor<'de> for SourceUnitVisitor {
    type Value = SourceUnit;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a checked source unit")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let function_index: u32 = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let instruction_start: u32 = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let instruction_end: u32 = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let bytes: SourceBytes = sequence
            .next_element_seed(SourceBytesSeed {
                limit: self.byte_limit,
            })?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        let offset: SourceOffset = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(4, &self))?;
        SourceUnit::new(
            function_index,
            instruction_start..instruction_end,
            bytes,
            offset,
        )
        .map_err(de::Error::custom)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut function_index: Option<u32> = None;
        let mut instruction_start: Option<u32> = None;
        let mut instruction_end: Option<u32> = None;
        let mut bytes: Option<SourceBytes> = None;
        let mut offset: Option<SourceOffset> = None;
        while let Some(field) = map.next_key::<SourceUnitField>()? {
            match field {
                SourceUnitField::FunctionIndex => {
                    if function_index.is_some() {
                        return Err(de::Error::duplicate_field("function_index"));
                    }
                    function_index = Some(map.next_value()?);
                }
                SourceUnitField::InstructionStart => {
                    if instruction_start.is_some() {
                        return Err(de::Error::duplicate_field("instruction_start"));
                    }
                    instruction_start = Some(map.next_value()?);
                }
                SourceUnitField::InstructionEnd => {
                    if instruction_end.is_some() {
                        return Err(de::Error::duplicate_field("instruction_end"));
                    }
                    instruction_end = Some(map.next_value()?);
                }
                SourceUnitField::Bytes => {
                    if bytes.is_some() {
                        return Err(de::Error::duplicate_field("bytes"));
                    }
                    bytes = Some(map.next_value_seed(SourceBytesSeed {
                        limit: self.byte_limit,
                    })?);
                }
                SourceUnitField::Offset => {
                    if offset.is_some() {
                        return Err(de::Error::duplicate_field("offset"));
                    }
                    offset = Some(map.next_value()?);
                }
            }
        }
        SourceUnit::new(
            function_index.ok_or_else(|| de::Error::missing_field("function_index"))?,
            instruction_start.ok_or_else(|| de::Error::missing_field("instruction_start"))?
                ..instruction_end.ok_or_else(|| de::Error::missing_field("instruction_end"))?,
            bytes.ok_or_else(|| de::Error::missing_field("bytes"))?,
            offset.ok_or_else(|| de::Error::missing_field("offset"))?,
        )
        .map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for SourceUnit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SourceUnitSeed {
            byte_limit: MAX_SOURCE_BYTES,
        }
        .deserialize(deserializer)
    }
}

impl SourceUnit {
    pub fn new(
        function_index: u32,
        instructions: std::ops::Range<u32>,
        bytes: SourceBytes,
        offset: SourceOffset,
    ) -> Result<Self, NirProvenanceError> {
        let original_byte_length: Option<usize> = match &bytes {
            SourceBytes::Original(value) => Some(value.len()),
            SourceBytes::Synthesized => None,
        };
        validate_source_unit(instructions.clone(), original_byte_length, offset)?;
        Ok(Self {
            function_index,
            instruction_start: instructions.start,
            instruction_end: instructions.end,
            bytes,
            offset,
        })
    }

    #[must_use]
    pub const fn function_index(&self) -> u32 {
        self.function_index
    }

    #[must_use]
    pub const fn instruction_start(&self) -> u32 {
        self.instruction_start
    }

    #[must_use]
    pub const fn instruction_end(&self) -> u32 {
        self.instruction_end
    }

    #[must_use]
    pub const fn instruction_count(&self) -> u32 {
        self.instruction_end - self.instruction_start
    }

    #[must_use]
    pub const fn bytes(&self) -> &SourceBytes {
        &self.bytes
    }

    #[must_use]
    pub fn original_bytes(&self) -> Option<&[u8]> {
        match &self.bytes {
            SourceBytes::Original(value) => Some(value),
            SourceBytes::Synthesized => None,
        }
    }

    #[must_use]
    pub const fn offset(&self) -> SourceOffset {
        self.offset
    }
}

fn validate_source_unit(
    instructions: std::ops::Range<u32>,
    original_byte_length: Option<usize>,
    offset: SourceOffset,
) -> Result<(), NirProvenanceError> {
    if instructions.start > instructions.end {
        return Err(NirProvenanceError::InvalidInstructionRange);
    }
    if original_byte_length == Some(0) {
        return Err(NirProvenanceError::EmptySourceBytes);
    }
    match (original_byte_length, offset) {
        (Some(length), SourceOffset::File(file_offset)) => {
            let byte_length: u64 =
                u64::try_from(length).map_err(|_error| NirProvenanceError::IndexOverflow)?;
            let end: u64 = file_offset.offset.checked_add(byte_length).ok_or(
                NirProvenanceError::FileRange {
                    offset: file_offset.offset,
                    byte_length,
                    file_length: file_offset.file_length,
                },
            )?;
            if end > file_offset.file_length {
                return Err(NirProvenanceError::FileRange {
                    offset: file_offset.offset,
                    byte_length,
                    file_length: file_offset.file_length,
                });
            }
        }
        (None, SourceOffset::Unavailable(SourceOffsetUnavailable::Synthesized)) => {}
        (None, _) => return Err(NirProvenanceError::SynthesizedOffset),
        (Some(_), SourceOffset::Unavailable(SourceOffsetUnavailable::Synthesized)) => {
            return Err(NirProvenanceError::OriginalBytesMarkedSynthesized);
        }
        (Some(_), _) => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NirProvenanceError {
    #[error("source unit instruction range is reversed")]
    InvalidInstructionRange,
    #[error("source unit original byte slice is empty")]
    EmptySourceBytes,
    #[error("synthesized source unit cannot carry a source offset")]
    SynthesizedOffset,
    #[error("original source bytes cannot use the synthesized offset reason")]
    OriginalBytesMarkedSynthesized,
    #[error("file offset {offset} exceeds file length {file_length}")]
    FileOffset { offset: u64, file_length: u64 },
    #[error(
        "source byte range at file offset {offset} with length {byte_length} exceeds file length {file_length}"
    )]
    FileRange {
        offset: u64,
        byte_length: u64,
        file_length: u64,
    },
    #[error("source unit function index {index} is outside {count} functions")]
    FunctionIndex { index: u32, count: usize },
    #[error(
        "source units do not cover function {function_index} at instruction {instruction_index}"
    )]
    InstructionCoverage {
        function_index: u32,
        instruction_index: u32,
    },
    #[error("source unit end {end} exceeds function {function_index} instruction count {count}")]
    InstructionEnd {
        function_index: u32,
        end: u32,
        count: usize,
    },
    #[error("source unit count exceeds the {limit} unit limit")]
    UnitLimit { limit: usize },
    #[error("source byte total exceeds the {limit}-byte limit")]
    ByteLimit { limit: usize },
    #[error("NIR element count exceeds the {limit} element limit")]
    ElementLimit { limit: usize },
    #[error("NIR string data exceeds the {limit}-byte limit")]
    StringByteLimit { limit: usize },
    #[error("NIR retained data exceeds the {limit}-byte limit")]
    RetainedByteLimit { limit: usize },
    #[error("NIR validation work exceeds the {limit} element limit")]
    WorkLimit { limit: usize },
    #[error("cannot allocate provenance storage for {requested} elements")]
    Allocation { requested: usize },
    #[error("function or instruction count exceeds the provenance index range")]
    IndexOverflow,
    #[error("function {function_index} contains source bytes that cannot be re-emitted")]
    UnavailableBytes { function_index: u32 },
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[rkyv(derive(Debug))]
pub struct NirArtifact {
    module: NirModule,
    source_units: Vec<SourceUnit>,
}

impl NirArtifact {
    pub fn new(
        module: NirModule,
        source_units: Vec<SourceUnit>,
    ) -> Result<Self, NirProvenanceError> {
        validate_artifact(&module, &source_units)?;
        Ok(Self {
            module,
            source_units,
        })
    }

    pub fn from_borrowed(
        module: NirModule,
        source_units: &[SourceUnitRef<'_>],
    ) -> Result<Self, NirProvenanceError> {
        validate_artifact(&module, source_units)?;
        let mut owned: Vec<SourceUnit> = Vec::new();
        owned
            .try_reserve_exact(source_units.len())
            .map_err(|_error| NirProvenanceError::Allocation {
                requested: source_units.len(),
            })?;
        let mut remaining_bytes: usize = MAX_SOURCE_BYTES;
        for unit in source_units.iter().copied() {
            let byte_length: usize = unit.original_bytes().map_or(0, <[u8]>::len);
            owned.push(unit.into_owned_with_limit(remaining_bytes)?);
            remaining_bytes =
                remaining_bytes
                    .checked_sub(byte_length)
                    .ok_or(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    })?;
        }
        Self::new(module, owned)
    }

    #[must_use]
    pub fn into_module(self) -> NirModule {
        self.module
    }

    #[must_use]
    pub const fn module(&self) -> &NirModule {
        &self.module
    }

    #[must_use]
    pub fn source_units(&self) -> &[SourceUnit] {
        &self.source_units
    }

    #[must_use]
    pub fn source_unit(&self, function_index: u32, instruction_index: u32) -> Option<&SourceUnit> {
        let position: usize = self.source_units.partition_point(|unit: &SourceUnit| {
            unit.function_index < function_index
                || (unit.function_index == function_index
                    && unit.instruction_start <= instruction_index)
        });
        let unit: &SourceUnit = self.source_units.get(position.checked_sub(1)?)?;
        (unit.function_index == function_index && instruction_index < unit.instruction_end)
            .then_some(unit)
    }

    pub fn reemit_original_bytes(
        &self,
        function_index: u32,
    ) -> Result<Vec<u8>, NirProvenanceError> {
        let function_index_usize: usize =
            usize::try_from(function_index).map_err(|_error| NirProvenanceError::IndexOverflow)?;
        if function_index_usize >= self.module.functions.len() {
            return Err(NirProvenanceError::FunctionIndex {
                index: function_index,
                count: self.module.functions.len(),
            });
        }
        let mut output_bytes: usize = 0;
        for unit in self
            .source_units
            .iter()
            .filter(|unit: &&SourceUnit| unit.function_index == function_index)
        {
            let SourceBytes::Original(bytes) = &unit.bytes else {
                return Err(NirProvenanceError::UnavailableBytes { function_index });
            };
            output_bytes =
                output_bytes
                    .checked_add(bytes.len())
                    .ok_or(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    })?;
        }
        let mut output: Vec<u8> = Vec::new();
        output.try_reserve_exact(output_bytes).map_err(|_error| {
            NirProvenanceError::Allocation {
                requested: output_bytes,
            }
        })?;
        for unit in self
            .source_units
            .iter()
            .filter(|unit: &&SourceUnit| unit.function_index == function_index)
        {
            let SourceBytes::Original(bytes) = &unit.bytes else {
                return Err(NirProvenanceError::UnavailableBytes { function_index });
            };
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }

    pub(crate) fn validate(&self) -> Result<(), NirProvenanceError> {
        validate_artifact(&self.module, &self.source_units)
    }

    pub(crate) fn validated(self) -> Result<Self, NirProvenanceError> {
        self.validate()?;
        Ok(self)
    }
}

fn validate_artifact(
    module: &NirModule,
    source_units: &[impl ProvenanceUnit],
) -> Result<(), NirProvenanceError> {
    validate_owned_resource_limits(module, source_units)?;
    if source_units.len() > MAX_SOURCE_UNITS {
        return Err(NirProvenanceError::UnitLimit {
            limit: MAX_SOURCE_UNITS,
        });
    }
    let mut byte_total: usize = 0;
    let mut cursor_by_function: Vec<u32> = Vec::new();
    cursor_by_function
        .try_reserve_exact(module.functions.len())
        .map_err(|_error| NirProvenanceError::Allocation {
            requested: module.functions.len(),
        })?;
    cursor_by_function.resize(module.functions.len(), 0);
    let mut previous_key: Option<(u32, u32)> = None;
    for unit in source_units {
        let function_index_value: u32 = unit.function_index();
        let instruction_start: u32 = unit.instruction_start();
        let instruction_end: u32 = unit.instruction_end();
        let original_byte_length: Option<usize> = unit.original_byte_length();
        validate_source_unit(
            instruction_start..instruction_end,
            original_byte_length,
            unit.offset(),
        )?;
        let key: (u32, u32) = (function_index_value, instruction_start);
        if previous_key.is_some_and(|previous: (u32, u32)| previous > key) {
            return Err(NirProvenanceError::InstructionCoverage {
                function_index: function_index_value,
                instruction_index: instruction_start,
            });
        }
        previous_key = Some(key);
        let function_index: usize = usize::try_from(function_index_value)
            .map_err(|_error| NirProvenanceError::IndexOverflow)?;
        let function: &NirFunction =
            module
                .functions
                .get(function_index)
                .ok_or(NirProvenanceError::FunctionIndex {
                    index: function_index_value,
                    count: module.functions.len(),
                })?;
        let instruction_count: u32 = u32::try_from(function.instructions.len())
            .map_err(|_error| NirProvenanceError::IndexOverflow)?;
        if instruction_end > instruction_count {
            return Err(NirProvenanceError::InstructionEnd {
                function_index: function_index_value,
                end: instruction_end,
                count: function.instructions.len(),
            });
        }
        let cursor: &mut u32 = cursor_by_function
            .get_mut(function_index)
            .ok_or(NirProvenanceError::IndexOverflow)?;
        if instruction_start != *cursor {
            return Err(NirProvenanceError::InstructionCoverage {
                function_index: function_index_value,
                instruction_index: *cursor,
            });
        }
        *cursor = instruction_end;
        if let Some(byte_length) = original_byte_length {
            byte_total =
                byte_total
                    .checked_add(byte_length)
                    .ok_or(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    })?;
            if byte_total > MAX_SOURCE_BYTES {
                return Err(NirProvenanceError::ByteLimit {
                    limit: MAX_SOURCE_BYTES,
                });
            }
        }
    }
    for (function_index, (function, cursor)) in module
        .functions
        .iter()
        .zip(cursor_by_function.iter())
        .enumerate()
    {
        let instruction_count: u32 = u32::try_from(function.instructions.len())
            .map_err(|_error| NirProvenanceError::IndexOverflow)?;
        if *cursor != instruction_count {
            return Err(NirProvenanceError::InstructionCoverage {
                function_index: u32::try_from(function_index)
                    .map_err(|_error| NirProvenanceError::IndexOverflow)?,
                instruction_index: *cursor,
            });
        }
    }
    Ok(())
}

trait ProvenanceUnit {
    fn function_index(&self) -> u32;
    fn instruction_start(&self) -> u32;
    fn instruction_end(&self) -> u32;
    fn original_byte_length(&self) -> Option<usize>;
    fn offset(&self) -> SourceOffset;
}

impl ProvenanceUnit for SourceUnit {
    fn function_index(&self) -> u32 {
        self.function_index
    }

    fn instruction_start(&self) -> u32 {
        self.instruction_start
    }

    fn instruction_end(&self) -> u32 {
        self.instruction_end
    }

    fn original_byte_length(&self) -> Option<usize> {
        self.original_bytes().map(<[u8]>::len)
    }

    fn offset(&self) -> SourceOffset {
        self.offset
    }
}

impl ProvenanceUnit for SourceUnitRef<'_> {
    fn function_index(&self) -> u32 {
        self.function_index
    }

    fn instruction_start(&self) -> u32 {
        self.instruction_start
    }

    fn instruction_end(&self) -> u32 {
        self.instruction_end
    }

    fn original_byte_length(&self) -> Option<usize> {
        self.original_bytes().map(<[u8]>::len)
    }

    fn offset(&self) -> SourceOffset {
        self.offset
    }
}

#[derive(Default)]
struct NirResourceBudget {
    functions: usize,
    instructions: usize,
    symbols: usize,
    nested_elements: usize,
    string_bytes: usize,
    retained_bytes: usize,
    work: usize,
}

impl NirResourceBudget {
    fn add_work(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        self.work = self
            .work
            .checked_add(count)
            .ok_or(NirProvenanceError::WorkLimit {
                limit: MAX_NIR_WORK,
            })?;
        if self.work > MAX_NIR_WORK {
            return Err(NirProvenanceError::WorkLimit {
                limit: MAX_NIR_WORK,
            });
        }
        Ok(())
    }

    fn add_retained<T>(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        let bytes: usize = std::mem::size_of::<T>().checked_mul(count).ok_or(
            NirProvenanceError::RetainedByteLimit {
                limit: MAX_NIR_RETAINED_BYTES,
            },
        )?;
        self.add_retained_bytes(bytes)
    }

    fn add_retained_bytes(&mut self, bytes: usize) -> Result<(), NirProvenanceError> {
        self.retained_bytes = self.retained_bytes.checked_add(bytes).ok_or(
            NirProvenanceError::RetainedByteLimit {
                limit: MAX_NIR_RETAINED_BYTES,
            },
        )?;
        if self.retained_bytes > MAX_NIR_RETAINED_BYTES {
            return Err(NirProvenanceError::RetainedByteLimit {
                limit: MAX_NIR_RETAINED_BYTES,
            });
        }
        Ok(())
    }

    fn add_functions(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        self.functions =
            self.functions
                .checked_add(count)
                .ok_or(NirProvenanceError::ElementLimit {
                    limit: MAX_NIR_ELEMENTS,
                })?;
        if self.functions > MAX_NIR_ELEMENTS {
            return Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS,
            });
        }
        self.add_work(count)?;
        self.add_retained::<NirFunction>(count)
    }

    fn add_instructions(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        self.instructions =
            self.instructions
                .checked_add(count)
                .ok_or(NirProvenanceError::ElementLimit {
                    limit: MAX_NIR_ELEMENTS,
                })?;
        if self.instructions > MAX_NIR_ELEMENTS {
            return Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS,
            });
        }
        self.add_work(count)?;
        self.add_retained::<NirInstr>(count)
    }

    fn add_symbols(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        self.symbols = self
            .symbols
            .checked_add(count)
            .ok_or(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS,
            })?;
        if self.symbols > MAX_NIR_ELEMENTS {
            return Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS,
            });
        }
        self.add_work(count)?;
        self.add_retained::<NirSymbol>(count)
    }

    fn add_nested<T>(&mut self, count: usize) -> Result<(), NirProvenanceError> {
        self.nested_elements =
            self.nested_elements
                .checked_add(count)
                .ok_or(NirProvenanceError::ElementLimit {
                    limit: MAX_NIR_ELEMENTS,
                })?;
        if self.nested_elements > MAX_NIR_ELEMENTS {
            return Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS,
            });
        }
        self.add_work(count)?;
        self.add_retained::<T>(count)
    }

    fn add_string(&mut self, length: usize) -> Result<(), NirProvenanceError> {
        self.string_bytes =
            self.string_bytes
                .checked_add(length)
                .ok_or(NirProvenanceError::StringByteLimit {
                    limit: MAX_NIR_STRING_BYTES,
                })?;
        if self.string_bytes > MAX_NIR_STRING_BYTES {
            return Err(NirProvenanceError::StringByteLimit {
                limit: MAX_NIR_STRING_BYTES,
            });
        }
        self.add_work(1)?;
        self.add_retained_bytes(length)
    }
}

fn validate_archived_strings(
    values: &rkyv::vec::ArchivedVec<rkyv::string::ArchivedString>,
    budget: &mut NirResourceBudget,
) -> Result<(), NirProvenanceError> {
    budget.add_nested::<String>(values.len())?;
    for value in values.as_slice() {
        budget.add_string(value.len())?;
    }
    Ok(())
}

fn validate_owned_strings(
    values: &[String],
    budget: &mut NirResourceBudget,
) -> Result<(), NirProvenanceError> {
    budget.add_nested::<String>(values.len())?;
    for value in values {
        budget.add_string(value.len())?;
    }
    Ok(())
}

fn validate_owned_operation(
    operation: &NirOp,
    budget: &mut NirResourceBudget,
) -> Result<(), NirProvenanceError> {
    match operation {
        NirOp::ExternCall { symbol } => budget.add_string(symbol.len())?,
        NirOp::RawLoad { addr, .. } => budget.add_string(addr.len())?,
        NirOp::RawStore { addr, value, .. } => {
            budget.add_string(addr.len())?;
            budget.add_string(value.len())?;
        }
        NirOp::Subpiece { src, .. } | NirOp::Copy { src, .. } => {
            budget.add_string(src.len())?;
        }
        NirOp::Deposit { cell, value, .. } => {
            budget.add_string(cell.len())?;
            budget.add_string(value.len())?;
        }
        NirOp::CallOther { effect } => {
            budget.add_string(effect.name.len())?;
            validate_owned_strings(&effect.reads, budget)?;
            validate_owned_strings(&effect.writes, budget)?;
        }
        NirOp::Value {
            inputs,
            input_sizes,
            ..
        } => {
            validate_owned_strings(inputs, budget)?;
            budget.add_nested::<u32>(input_sizes.len())?;
        }
        NirOp::Piece { high, low, .. } => {
            budget.add_string(high.len())?;
            budget.add_string(low.len())?;
        }
        NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Load
        | NirOp::Store
        | NirOp::Call { .. }
        | NirOp::IndirectCall
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Phi
        | NirOp::Return
        | NirOp::Interrupt
        | NirOp::Unmodeled { .. }
        | NirOp::NoReturnCall { .. }
        | NirOp::TailCall { .. } => {}
    }
    Ok(())
}

fn validate_owned_resource_limits(
    module: &NirModule,
    source_units: &[impl ProvenanceUnit],
) -> Result<(), NirProvenanceError> {
    if source_units.len() > MAX_SOURCE_UNITS {
        return Err(NirProvenanceError::UnitLimit {
            limit: MAX_SOURCE_UNITS,
        });
    }
    let mut budget: NirResourceBudget = NirResourceBudget::default();
    budget.add_retained::<NirArtifact>(1)?;
    budget.add_functions(module.functions.len())?;
    budget.add_symbols(module.symbols.len())?;
    budget.add_work(source_units.len())?;
    budget.add_retained::<SourceUnit>(source_units.len())?;
    for function in &module.functions {
        budget.add_string(function.name.len())?;
        budget.add_string(function.source.label.len())?;
        budget.add_instructions(function.instructions.len())?;
        for instruction in &function.instructions {
            budget.add_string(instruction.mnemonic.len())?;
            validate_owned_strings(&instruction.operands, &mut budget)?;
            budget.add_string(instruction.source.label.len())?;
            validate_owned_operation(&instruction.op, &mut budget)?;
        }
    }
    for symbol in &module.symbols {
        budget.add_string(symbol.name.len())?;
    }
    let mut byte_total: usize = 0;
    for unit in source_units {
        if let Some(byte_length) = unit.original_byte_length() {
            byte_total =
                byte_total
                    .checked_add(byte_length)
                    .ok_or(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    })?;
            if byte_total > MAX_SOURCE_BYTES {
                return Err(NirProvenanceError::ByteLimit {
                    limit: MAX_SOURCE_BYTES,
                });
            }
            budget.add_retained_bytes(byte_length)?;
        }
    }
    Ok(())
}

fn validate_archived_operation(
    operation: &ArchivedNirOp,
    budget: &mut NirResourceBudget,
) -> Result<(), NirProvenanceError> {
    match operation {
        ArchivedNirOp::ExternCall { symbol } => budget.add_string(symbol.len())?,
        ArchivedNirOp::RawLoad { addr, .. } => budget.add_string(addr.len())?,
        ArchivedNirOp::RawStore { addr, value, .. } => {
            budget.add_string(addr.len())?;
            budget.add_string(value.len())?;
        }
        ArchivedNirOp::Subpiece { src, .. } | ArchivedNirOp::Copy { src, .. } => {
            budget.add_string(src.len())?;
        }
        ArchivedNirOp::Deposit { cell, value, .. } => {
            budget.add_string(cell.len())?;
            budget.add_string(value.len())?;
        }
        ArchivedNirOp::CallOther { effect } => {
            budget.add_string(effect.name.len())?;
            validate_archived_strings(&effect.reads, budget)?;
            validate_archived_strings(&effect.writes, budget)?;
        }
        ArchivedNirOp::Value {
            inputs,
            input_sizes,
            ..
        } => {
            validate_archived_strings(inputs, budget)?;
            budget.add_nested::<u32>(input_sizes.len())?;
        }
        ArchivedNirOp::Piece { high, low, .. } => {
            budget.add_string(high.len())?;
            budget.add_string(low.len())?;
        }
        ArchivedNirOp::Nop
        | ArchivedNirOp::Const
        | ArchivedNirOp::BinOp { .. }
        | ArchivedNirOp::Load
        | ArchivedNirOp::Store
        | ArchivedNirOp::Call { .. }
        | ArchivedNirOp::IndirectCall
        | ArchivedNirOp::Branch { .. }
        | ArchivedNirOp::CondBranch { .. }
        | ArchivedNirOp::Phi
        | ArchivedNirOp::Return
        | ArchivedNirOp::Interrupt
        | ArchivedNirOp::Unmodeled { .. }
        | ArchivedNirOp::NoReturnCall { .. }
        | ArchivedNirOp::TailCall { .. } => {}
    }
    Ok(())
}

impl ArchivedNirArtifact {
    pub(crate) fn validate_resource_limits(&self) -> Result<(), NirProvenanceError> {
        let archived_functions: &[ArchivedNirFunction] = self.module.functions.as_slice();
        let archived_symbols: &[ArchivedNirSymbol] = self.module.symbols.as_slice();
        let archived_units: &[ArchivedSourceUnit] = self.source_units.as_slice();
        let unit_limit: u64 =
            u64::try_from(MAX_SOURCE_UNITS).map_err(|_error| NirProvenanceError::IndexOverflow)?;
        let unit_count: u64 = u64::try_from(archived_units.len())
            .map_err(|_error| NirProvenanceError::IndexOverflow)?;
        if unit_count > unit_limit {
            return Err(NirProvenanceError::UnitLimit {
                limit: MAX_SOURCE_UNITS,
            });
        }
        let mut budget: NirResourceBudget = NirResourceBudget::default();
        budget.add_retained::<NirArtifact>(1)?;
        budget.add_functions(archived_functions.len())?;
        budget.add_symbols(archived_symbols.len())?;
        budget.add_work(archived_units.len())?;
        budget.add_retained::<SourceUnit>(archived_units.len())?;
        for function in archived_functions {
            budget.add_string(function.name.len())?;
            budget.add_string(function.source.label.len())?;
            let archived_instructions: &[ArchivedNirInstr] = function.instructions.as_slice();
            budget.add_instructions(archived_instructions.len())?;
            for instruction in archived_instructions {
                budget.add_string(instruction.mnemonic.len())?;
                validate_archived_strings(&instruction.operands, &mut budget)?;
                budget.add_string(instruction.source.label.len())?;
                validate_archived_operation(&instruction.op, &mut budget)?;
            }
        }
        for symbol in archived_symbols {
            budget.add_string(symbol.name.len())?;
        }
        let byte_limit: u64 =
            u64::try_from(MAX_SOURCE_BYTES).map_err(|_error| NirProvenanceError::IndexOverflow)?;
        let mut byte_total: u64 = 0;
        for unit in archived_units {
            if let ArchivedSourceBytes::Original(bytes) = &unit.bytes {
                let byte_length: u64 =
                    u64::try_from(bytes.len()).map_err(|_error| NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    })?;
                byte_total =
                    byte_total
                        .checked_add(byte_length)
                        .ok_or(NirProvenanceError::ByteLimit {
                            limit: MAX_SOURCE_BYTES,
                        })?;
                if byte_total > byte_limit {
                    return Err(NirProvenanceError::ByteLimit {
                        limit: MAX_SOURCE_BYTES,
                    });
                }
                budget.add_retained_bytes(usize::try_from(byte_length).map_err(|_error| {
                    NirProvenanceError::RetainedByteLimit {
                        limit: MAX_NIR_RETAINED_BYTES,
                    }
                })?)?;
            }
        }
        Ok(())
    }
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
    use crate::codec::{decode_nir, decode_nir_artifact, encode_nir, encode_nir_artifact};

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

    #[test]
    fn artifact_encode_revalidates_private_fields() {
        let invalid: NirArtifact = NirArtifact {
            module: NirModule {
                source_hash: [0x77; 32],
                lang: SourceLang::NativeX86,
                functions: vec![NirFunction {
                    name: "invalid".to_owned(),
                    address: 0x1000,
                    end: 0x1001,
                    is_export: false,
                    instructions: vec![instr(0x1000, NirOp::Return, "ret")],
                    source: SourceRef::new(SourceLang::NativeX86, 0x1000),
                }],
                symbols: Vec::new(),
            },
            source_units: Vec::new(),
        };
        assert!(encode_nir_artifact(&invalid).is_err());
    }

    #[test]
    fn serde_rejects_invalid_file_offsets() {
        let fields: [(&str, u64); 2] = [("offset", 2), ("file_length", 1)];
        let deserializer: serde::de::value::MapDeserializer<_, serde::de::value::Error> =
            serde::de::value::MapDeserializer::new(fields.into_iter());
        let decoded: Result<FileSourceOffset, serde::de::value::Error> =
            <FileSourceOffset as serde::Deserialize<'_>>::deserialize(deserializer);
        assert!(decoded.is_err());
    }

    #[test]
    fn bounded_byte_deserialization_does_not_overreserve_past_its_ceiling() {
        struct UnderstatedBytes {
            emitted: usize,
            total: usize,
            hint: usize,
        }

        impl Iterator for UnderstatedBytes {
            type Item = u8;

            fn next(&mut self) -> Option<Self::Item> {
                if self.emitted == self.total {
                    return None;
                }
                self.emitted += 1;
                Some(0x90)
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.hint, Some(self.hint))
            }
        }

        let sequence: serde::de::value::SeqDeserializer<_, serde::de::value::Error> =
            serde::de::value::SeqDeserializer::new(UnderstatedBytes {
                emitted: 0,
                total: 4,
                hint: 3,
            });
        let bytes: Vec<u8> = BoundedBytesSeed { limit: 4 }
            .deserialize(sequence)
            .expect("bounded byte sequence");
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes.capacity(), 4);
    }

    #[test]
    fn archived_resource_preflight_rejects_oversized_source_bytes() {
        let invalid: NirArtifact = NirArtifact {
            module: NirModule {
                source_hash: [0x66; 32],
                lang: SourceLang::NativeX86,
                functions: vec![NirFunction {
                    name: "empty".to_owned(),
                    address: 0x1000,
                    end: 0x1000,
                    is_export: false,
                    instructions: Vec::new(),
                    source: SourceRef::new(SourceLang::NativeX86, 0x1000),
                }],
                symbols: Vec::new(),
            },
            source_units: vec![SourceUnit {
                function_index: 0,
                instruction_start: 0,
                instruction_end: 0,
                bytes: SourceBytes::Original(vec![0x90; MAX_SOURCE_BYTES + 1]),
                offset: SourceOffset::MemoryImage(0x1000),
            }],
        };
        let bytes: rkyv::util::AlignedVec =
            rkyv::to_bytes::<rkyv::rancor::Error>(&invalid).expect("archive invalid private state");
        let archived: &ArchivedNirArtifact =
            rkyv::access::<ArchivedNirArtifact, rkyv::rancor::Error>(&bytes)
                .expect("access structurally valid archive");
        assert!(matches!(
            archived.validate_resource_limits(),
            Err(NirProvenanceError::ByteLimit {
                limit: MAX_SOURCE_BYTES
            })
        ));
    }

    fn archived_resource_result(module: NirModule) -> Result<(), NirProvenanceError> {
        let invalid: NirArtifact = NirArtifact {
            module,
            source_units: Vec::new(),
        };
        let bytes: rkyv::util::AlignedVec =
            rkyv::to_bytes::<rkyv::rancor::Error>(&invalid).expect("archive resource probe");
        let archived: &ArchivedNirArtifact =
            rkyv::access::<ArchivedNirArtifact, rkyv::rancor::Error>(&bytes)
                .expect("access structurally valid archive");
        assert!(decode_nir_artifact(&bytes).is_err());
        archived.validate_resource_limits()
    }

    fn empty_function() -> NirFunction {
        NirFunction {
            name: String::new(),
            address: 0,
            end: 0,
            is_export: false,
            instructions: Vec::new(),
            source: SourceRef::new(SourceLang::Unknown, 0),
        }
    }

    fn empty_module() -> NirModule {
        NirModule::new([0; 32], SourceLang::Unknown)
    }

    #[test]
    fn resource_budget_rejects_exact_aggregate_limits_plus_one() {
        for retained_element_bytes in [
            std::mem::size_of::<NirFunction>(),
            std::mem::size_of::<NirInstr>(),
            std::mem::size_of::<NirSymbol>(),
            std::mem::size_of::<String>(),
        ] {
            assert!(
                retained_element_bytes
                    .checked_mul(MAX_NIR_ELEMENTS)
                    .is_some_and(|bytes: usize| bytes <= MAX_NIR_RETAINED_BYTES)
            );
        }
        let mut functions: NirResourceBudget = NirResourceBudget::default();
        functions
            .add_functions(MAX_NIR_ELEMENTS)
            .expect("declared function maximum");
        assert!(matches!(
            functions.add_functions(1),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
        let mut instructions: NirResourceBudget = NirResourceBudget::default();
        instructions
            .add_instructions(MAX_NIR_ELEMENTS)
            .expect("declared instruction maximum");
        assert!(matches!(
            instructions.add_instructions(1),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
        let mut symbols: NirResourceBudget = NirResourceBudget::default();
        symbols
            .add_symbols(MAX_NIR_ELEMENTS)
            .expect("declared symbol maximum");
        assert!(matches!(
            symbols.add_symbols(1),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
        let mut nested: NirResourceBudget = NirResourceBudget::default();
        nested
            .add_nested::<String>(MAX_NIR_ELEMENTS)
            .expect("declared nested element maximum");
        assert!(matches!(
            nested.add_nested::<String>(1),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
        let mut retained: NirResourceBudget = NirResourceBudget {
            retained_bytes: MAX_NIR_RETAINED_BYTES,
            ..NirResourceBudget::default()
        };
        assert!(matches!(
            retained.add_retained_bytes(1),
            Err(NirProvenanceError::RetainedByteLimit {
                limit: MAX_NIR_RETAINED_BYTES
            })
        ));

        let mut work: NirResourceBudget = NirResourceBudget {
            work: MAX_NIR_WORK,
            ..NirResourceBudget::default()
        };
        assert!(matches!(
            work.add_work(1),
            Err(NirProvenanceError::WorkLimit {
                limit: MAX_NIR_WORK
            })
        ));
    }

    #[test]
    fn archived_module_preflight_accepts_maximum_functions_and_refuses_one_more() {
        let maximum_functions: Vec<NirFunction> = vec![empty_function(); MAX_NIR_ELEMENTS];
        let maximum: NirArtifact = NirArtifact::new(
            NirModule {
                source_hash: [0; 32],
                lang: SourceLang::Unknown,
                functions: maximum_functions,
                symbols: Vec::new(),
            },
            Vec::new(),
        )
        .expect("coherent maximum function shape");
        let encoded: Vec<u8> = encode_nir_artifact(&maximum).expect("encode maximum shape");
        let decoded: NirArtifact = decode_nir_artifact(&encoded).expect("decode maximum shape");
        assert_eq!(decoded.module().functions.len(), MAX_NIR_ELEMENTS);
        drop(decoded);
        drop(encoded);
        drop(maximum);

        let mut over_limit: NirModule = empty_module();
        over_limit.functions = vec![empty_function(); MAX_NIR_ELEMENTS + 1];
        assert!(matches!(
            archived_resource_result(over_limit),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
    }

    #[test]
    fn archived_module_preflight_refuses_other_exact_element_limits_plus_one() {
        let mut instruction_module: NirModule = empty_module();
        let mut instruction_function: NirFunction = empty_function();
        instruction_function.instructions = vec![instr(0, NirOp::Nop, ""); MAX_NIR_ELEMENTS + 1];
        instruction_module.functions.push(instruction_function);
        assert!(matches!(
            archived_resource_result(instruction_module),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));

        let mut symbol_module: NirModule = empty_module();
        symbol_module.symbols = vec![
            NirSymbol {
                address: 0,
                name: String::new(),
                kind: SymbolKind::Label,
            };
            MAX_NIR_ELEMENTS + 1
        ];
        assert!(matches!(
            archived_resource_result(symbol_module),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));

        let mut nested_module: NirModule = empty_module();
        let mut nested_function: NirFunction = empty_function();
        let mut nested_instruction: NirInstr = instr(0, NirOp::Nop, "");
        nested_instruction.operands = vec![String::new(); MAX_NIR_ELEMENTS + 1];
        nested_function.instructions.push(nested_instruction);
        nested_module.functions.push(nested_function);
        assert!(matches!(
            archived_resource_result(nested_module),
            Err(NirProvenanceError::ElementLimit {
                limit: MAX_NIR_ELEMENTS
            })
        ));
    }

    #[test]
    fn archived_module_preflight_refuses_exact_string_byte_limit_plus_one() {
        let mut module: NirModule = empty_module();
        let mut function: NirFunction = empty_function();
        function.name = "x".repeat(MAX_NIR_STRING_BYTES + 1);
        module.functions.push(function);
        assert!(matches!(
            archived_resource_result(module),
            Err(NirProvenanceError::StringByteLimit {
                limit: MAX_NIR_STRING_BYTES
            })
        ));
    }

    #[test]
    fn archived_preflight_accepts_maximum_source_units_and_refuses_one_more() {
        let source_unit: SourceUnit = SourceUnit::new(
            0,
            0..0,
            SourceBytes::Synthesized,
            SourceOffset::Unavailable(SourceOffsetUnavailable::Synthesized),
        )
        .expect("zero-output source unit");
        let maximum: NirArtifact = NirArtifact::new(
            NirModule {
                source_hash: [0; 32],
                lang: SourceLang::Unknown,
                functions: vec![empty_function()],
                symbols: Vec::new(),
            },
            vec![source_unit.clone(); MAX_SOURCE_UNITS],
        )
        .expect("coherent maximum source-unit shape");
        let encoded: Vec<u8> = encode_nir_artifact(&maximum).expect("encode source-unit maximum");
        let decoded: NirArtifact =
            decode_nir_artifact(&encoded).expect("decode source-unit maximum");
        assert_eq!(decoded.source_units().len(), MAX_SOURCE_UNITS);
        drop(decoded);
        drop(encoded);
        drop(maximum);

        let over_limit: NirArtifact = NirArtifact {
            module: NirModule {
                source_hash: [0; 32],
                lang: SourceLang::Unknown,
                functions: vec![empty_function()],
                symbols: Vec::new(),
            },
            source_units: vec![source_unit; MAX_SOURCE_UNITS + 1],
        };
        let encoded: rkyv::util::AlignedVec =
            rkyv::to_bytes::<rkyv::rancor::Error>(&over_limit).expect("archive over-limit units");
        let archived: &ArchivedNirArtifact =
            rkyv::access::<ArchivedNirArtifact, rkyv::rancor::Error>(&encoded)
                .expect("access over-limit units");
        assert!(decode_nir_artifact(&encoded).is_err());
        assert!(matches!(
            archived.validate_resource_limits(),
            Err(NirProvenanceError::UnitLimit {
                limit: MAX_SOURCE_UNITS
            })
        ));
    }
}
