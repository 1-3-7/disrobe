use std::collections::BTreeMap;
use std::marker::PhantomData;

use disrobe_core::recovery::ConfidenceTier;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::defuse::{DefUse, ValueId, def_use};
use crate::types::{
    CallOtherEffect, NirArtifact, NirFunction, NirInstr, NirModule, NirOp, SourceBytes, SourceLang,
    SourceUnit,
};

pub const MAX_EFFECT_ROWS: usize = 1_048_576;
pub const MAX_EFFECT_MODELS: usize = 65_536;

const HARD_EFFECT_COUNT: usize = 18;
const HARD_EFFECT_MASK: u32 = (1_u32 << HARD_EFFECT_COUNT) - 1;
const MAX_WIRE_EFFECT_LABELS: usize = 64;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum HardEffect {
    MemoryRead = 0,
    MemoryWrite = 1,
    StackRead = 2,
    StackWrite = 3,
    RegisterRead = 4,
    RegisterWrite = 5,
    FlagWrite = 6,
    Syscall = 7,
    ImportCall = 8,
    IndirectCall = 9,
    IndirectJump = 10,
    Return = 11,
    ExceptionRaise = 12,
    ExceptionCatch = 13,
    AtomicReadModifyWrite = 14,
    MemoryFence = 15,
    PrivilegedOperation = 16,
    Unmodelled = 17,
}

impl HardEffect {
    pub const ALL: [Self; HARD_EFFECT_COUNT] = [
        Self::MemoryRead,
        Self::MemoryWrite,
        Self::StackRead,
        Self::StackWrite,
        Self::RegisterRead,
        Self::RegisterWrite,
        Self::FlagWrite,
        Self::Syscall,
        Self::ImportCall,
        Self::IndirectCall,
        Self::IndirectJump,
        Self::Return,
        Self::ExceptionRaise,
        Self::ExceptionCatch,
        Self::AtomicReadModifyWrite,
        Self::MemoryFence,
        Self::PrivilegedOperation,
        Self::Unmodelled,
    ];

    #[must_use]
    pub const fn bit(self) -> u32 {
        1_u32 << (self as u8)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemoryRead => "memory-read",
            Self::MemoryWrite => "memory-write",
            Self::StackRead => "stack-read",
            Self::StackWrite => "stack-write",
            Self::RegisterRead => "register-read",
            Self::RegisterWrite => "register-write",
            Self::FlagWrite => "flag-write",
            Self::Syscall => "syscall",
            Self::ImportCall => "import-call",
            Self::IndirectCall => "indirect-call",
            Self::IndirectJump => "indirect-jump",
            Self::Return => "return",
            Self::ExceptionRaise => "exception-raise",
            Self::ExceptionCatch => "exception-catch",
            Self::AtomicReadModifyWrite => "atomic-read-modify-write",
            Self::MemoryFence => "memory-fence",
            Self::PrivilegedOperation => "privileged-operation",
            Self::Unmodelled => "unmodelled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct HardEffects(u32);

impl HardEffects {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn of(effect: HardEffect) -> Self {
        Self(effect.bit())
    }

    pub const fn from_bits(bits: u32) -> Result<Self, EffectRowError> {
        if bits & !HARD_EFFECT_MASK == 0 {
            Ok(Self(bits))
        } else {
            Err(EffectRowError::UndefinedEffectBits { bits })
        }
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn with(self, effect: HardEffect) -> Self {
        Self(self.0 | effect.bit())
    }

    #[must_use]
    pub const fn without(self, effect: HardEffect) -> Self {
        Self(self.0 & !effect.bit())
    }

    #[must_use]
    pub const fn contains(self, effect: HardEffect) -> bool {
        self.0 & effect.bit() != 0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    pub fn iter(self) -> impl Iterator<Item = HardEffect> {
        HardEffect::ALL
            .into_iter()
            .filter(move |effect: &HardEffect| self.contains(*effect))
    }

    #[must_use]
    pub const fn first(self) -> Option<HardEffect> {
        let mut index: usize = 0;
        while index < HARD_EFFECT_COUNT {
            let effect: HardEffect = HardEffect::ALL[index];
            if self.0 & effect.bit() != 0 {
                return Some(effect);
            }
            index += 1;
        }
        None
    }
}

impl Serialize for HardEffects {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

struct HardEffectsVisitor;

impl<'de> Visitor<'de> for HardEffectsVisitor {
    type Value = HardEffects;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded sequence of hard effect labels")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut effects: HardEffects = HardEffects::empty();
        let mut seen: usize = 0;
        while let Some(effect) = sequence.next_element::<HardEffect>()? {
            seen += 1;
            if seen > MAX_WIRE_EFFECT_LABELS {
                return Err(de::Error::custom(EffectTableError::EffectLabelLimit {
                    limit: MAX_WIRE_EFFECT_LABELS,
                }));
            }
            effects = effects.with(effect);
        }
        Ok(effects)
    }
}

impl<'de> Deserialize<'de> for HardEffects {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(HardEffectsVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum EffectProvenance {
    Encoding,
    ResolvedImport,
    ResolvedSyscall,
    Unknown,
}

impl EffectProvenance {
    pub const ALL: [Self; 4] = [
        Self::Encoding,
        Self::ResolvedImport,
        Self::ResolvedSyscall,
        Self::Unknown,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::ResolvedImport => "resolved-import",
            Self::ResolvedSyscall => "resolved-syscall",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SourceEncoding {
    Present,
    Synthesized,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum SyscallNumber {
    Resolved(u32),
    ArchitectureAmbiguous,
    Unresolved,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NativeEffect {
    MemoryLoad,
    MemoryStore,
    RegisterTransfer,
    FlagUpdate,
    DirectCall,
    IndirectCall,
    ImportCall,
    TailCall,
    NoReturnCall,
    Syscall(SyscallNumber),
    IndirectJump,
    Return,
    Fence,
    PrivilegedInstruction,
    AtomicReadModifyWrite,
    UserOperation,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum CilEffect {
    NewObject,
    NewArray,
    Box,
    Unbox,
    LoadField,
    StoreField,
    LoadStaticField,
    StoreStaticField,
    LoadElement,
    StoreElement,
    LoadIndirect,
    StoreIndirect,
    InitBlock,
    CopyBlock,
    StackAllocate,
    ManagedCall,
    VirtualCall,
    IndirectCall,
    Throw,
    Rethrow,
    EndFinally,
    EndFilter,
    LeaveRegion,
    VolatileAccess,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum JvmEffect {
    NewObject,
    NewArray,
    GetField,
    PutField,
    GetStatic,
    PutStatic,
    ArrayLoad,
    ArrayStore,
    InvokeVirtual,
    InvokeStatic,
    InvokeSpecial,
    InvokeInterface,
    InvokeDynamic,
    Invoke,
    AThrow,
    MonitorEnter,
    MonitorExit,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DalvikEffect {
    NewInstance,
    NewArray,
    InstanceGet,
    InstancePut,
    StaticGet,
    StaticPut,
    ArrayGet,
    ArrayPut,
    InvokeVirtual,
    InvokeSuper,
    InvokeDirect,
    InvokeStatic,
    InvokeInterface,
    InvokePolymorphic,
    Invoke,
    Throw,
    MoveException,
    MonitorEnter,
    MonitorExit,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum WasmEffect {
    LinearMemoryLoad,
    LinearMemoryStore,
    MemoryGrow,
    MemorySize,
    MemoryCopy,
    MemoryFill,
    MemoryInit,
    TableGet,
    TableSet,
    GlobalGet,
    GlobalSet,
    Call,
    CallIndirect,
    CallRef,
    AtomicReadModifyWrite,
    AtomicWait,
    AtomicNotify,
    Fence,
    Throw,
    Catch,
    Return,
    Unreachable,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Avm2Effect {
    GetProperty,
    SetProperty,
    DeleteProperty,
    GetSlot,
    SetSlot,
    GetGlobalSlot,
    SetGlobalSlot,
    ConstructObject,
    ConstructProperty,
    ConstructSuper,
    CallProperty,
    CallMethod,
    CallSuper,
    Throw,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BeamEffect {
    LocalCall,
    ExternalCall,
    ApplyCall,
    BifCall,
    Send,
    Receive,
    HeapAllocate,
    TupleGet,
    TupleSet,
    Raise,
    EnterProtectedRegion,
    LeaveProtectedRegion,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum LuaEffect {
    TableGet,
    TableSet,
    UpvalueGet,
    UpvalueSet,
    GlobalGet,
    GlobalSet,
    NewTable,
    Closure,
    Call,
    TailCall,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum PythonEffect {
    LoadSubscript,
    StoreSubscript,
    Call,
    RaiseException,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum YarvEffect {
    InstanceVariableGet,
    InstanceVariableSet,
    GlobalGet,
    GlobalSet,
    ClassVariableGet,
    ClassVariableSet,
    ConstantGet,
    ConstantSet,
    Send,
    InvokeSuper,
    InvokeBlock,
    InvokeBuiltin,
    Throw,
    Return,
    Unmodelled,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum DialectEffect {
    None,
    Native(NativeEffect),
    Cil(CilEffect),
    Jvm(JvmEffect),
    Dalvik(DalvikEffect),
    Wasm(WasmEffect),
    Avm2(Avm2Effect),
    Beam(BeamEffect),
    Lua(LuaEffect),
    Python(PythonEffect),
    Yarv(YarvEffect),
}

impl DialectEffect {
    #[must_use]
    pub const fn belongs_to(self, lang: SourceLang) -> bool {
        matches!(
            (self, lang),
            (Self::None, _)
                | (
                    Self::Native(_),
                    SourceLang::NativeX86 | SourceLang::NativeArm | SourceLang::NativeMips
                )
                | (Self::Cil(_), SourceLang::Cil)
                | (Self::Jvm(_), SourceLang::Jvm)
                | (Self::Dalvik(_), SourceLang::Dalvik)
                | (Self::Wasm(_), SourceLang::Wasm)
                | (Self::Avm2(_), SourceLang::Avm2)
                | (Self::Beam(_), SourceLang::Beam)
                | (Self::Lua(_), SourceLang::Lua)
                | (Self::Python(_), SourceLang::Python)
                | (Self::Yarv(_), SourceLang::Yarv)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EffectRowError {
    #[error("effect bit set {bits:#x} contains undefined hard effect bits")]
    UndefinedEffectBits { bits: u32 },
    #[error("hard effect {} appears under more than one provenance", .effect.label())]
    ProvenanceOverlap { effect: HardEffect },
    #[error("conditional hard effect {} is not derived by the row", .effect.label())]
    ConditionalNotDerived { effect: HardEffect },
    #[error("an atomic read-modify-write cannot also report a separate memory read or write")]
    AtomicSplit,
    #[error("dialect effect does not belong to source language {}", .lang.label())]
    DialectLangMismatch { lang: SourceLang },
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectRow {
    encoding: HardEffects,
    import: HardEffects,
    syscall: HardEffects,
    unknown: HardEffects,
    conditional: HardEffects,
    dialect: DialectEffect,
    lang: SourceLang,
    source_encoding: SourceEncoding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectRowWire {
    encoding: HardEffects,
    import: HardEffects,
    syscall: HardEffects,
    unknown: HardEffects,
    conditional: HardEffects,
    dialect: DialectEffect,
    lang: SourceLang,
    source_encoding: SourceEncoding,
}

impl TryFrom<EffectRowWire> for EffectRow {
    type Error = EffectRowError;

    fn try_from(wire: EffectRowWire) -> Result<Self, Self::Error> {
        Self::from_parts(
            wire.lang,
            [
                (EffectProvenance::Encoding, wire.encoding),
                (EffectProvenance::ResolvedImport, wire.import),
                (EffectProvenance::ResolvedSyscall, wire.syscall),
                (EffectProvenance::Unknown, wire.unknown),
            ],
            wire.conditional,
            wire.dialect,
            wire.source_encoding,
        )
    }
}

impl<'de> Deserialize<'de> for EffectRow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire: EffectRowWire = EffectRowWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(de::Error::custom)
    }
}

impl EffectRow {
    #[must_use]
    pub const fn builder(lang: SourceLang) -> EffectRowBuilder {
        EffectRowBuilder::new(lang)
    }

    #[must_use]
    pub const fn none(lang: SourceLang) -> Self {
        Self {
            encoding: HardEffects::empty(),
            import: HardEffects::empty(),
            syscall: HardEffects::empty(),
            unknown: HardEffects::empty(),
            conditional: HardEffects::empty(),
            dialect: DialectEffect::None,
            lang,
            source_encoding: SourceEncoding::Unknown,
        }
    }

    #[must_use]
    pub const fn unknown(lang: SourceLang) -> Self {
        Self {
            encoding: HardEffects::empty(),
            import: HardEffects::empty(),
            syscall: HardEffects::empty(),
            unknown: HardEffects::of(HardEffect::Unmodelled),
            conditional: HardEffects::empty(),
            dialect: DialectEffect::None,
            lang,
            source_encoding: SourceEncoding::Unknown,
        }
    }

    pub fn from_parts(
        lang: SourceLang,
        provenances: [(EffectProvenance, HardEffects); 4],
        conditional: HardEffects,
        dialect: DialectEffect,
        source_encoding: SourceEncoding,
    ) -> Result<Self, EffectRowError> {
        let mut row: Self = Self::none(lang);
        row.conditional = conditional;
        row.dialect = dialect;
        row.source_encoding = source_encoding;
        for (provenance, effects) in provenances {
            match provenance {
                EffectProvenance::Encoding => row.encoding = effects,
                EffectProvenance::ResolvedImport => row.import = effects,
                EffectProvenance::ResolvedSyscall => row.syscall = effects,
                EffectProvenance::Unknown => row.unknown = effects,
            }
        }
        row.validate()?;
        Ok(row)
    }

    pub const fn validate(&self) -> Result<(), EffectRowError> {
        let sets: [HardEffects; 5] = [
            self.encoding,
            self.import,
            self.syscall,
            self.unknown,
            self.conditional,
        ];
        let mut index: usize = 0;
        while index < sets.len() {
            if let Err(error) = HardEffects::from_bits(sets[index].bits()) {
                return Err(error);
            }
            index += 1;
        }

        let mut seen: HardEffects = HardEffects::empty();
        let provenance_sets: [HardEffects; 4] =
            [self.encoding, self.import, self.syscall, self.unknown];
        let mut set_index: usize = 0;
        while set_index < provenance_sets.len() {
            let overlap: HardEffects = seen.intersection(provenance_sets[set_index]);
            if let Some(effect) = overlap.first() {
                return Err(EffectRowError::ProvenanceOverlap { effect });
            }
            seen = seen.union(provenance_sets[set_index]);
            set_index += 1;
        }

        if let Some(effect) = self.conditional.difference(seen).first() {
            return Err(EffectRowError::ConditionalNotDerived { effect });
        }

        if seen.contains(HardEffect::AtomicReadModifyWrite)
            && (seen.contains(HardEffect::MemoryRead) || seen.contains(HardEffect::MemoryWrite))
        {
            return Err(EffectRowError::AtomicSplit);
        }

        if self.dialect.belongs_to(self.lang) {
            Ok(())
        } else {
            Err(EffectRowError::DialectLangMismatch { lang: self.lang })
        }
    }

    #[must_use]
    pub const fn effects(self) -> HardEffects {
        self.encoding
            .union(self.import)
            .union(self.syscall)
            .union(self.unknown)
    }

    #[must_use]
    pub const fn contains(self, effect: HardEffect) -> bool {
        self.effects().contains(effect)
    }

    #[must_use]
    pub const fn provenance_of(self, effect: HardEffect) -> Option<EffectProvenance> {
        if self.encoding.contains(effect) {
            Some(EffectProvenance::Encoding)
        } else if self.import.contains(effect) {
            Some(EffectProvenance::ResolvedImport)
        } else if self.syscall.contains(effect) {
            Some(EffectProvenance::ResolvedSyscall)
        } else if self.unknown.contains(effect) {
            Some(EffectProvenance::Unknown)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn provenance_set(self, provenance: EffectProvenance) -> HardEffects {
        match provenance {
            EffectProvenance::Encoding => self.encoding,
            EffectProvenance::ResolvedImport => self.import,
            EffectProvenance::ResolvedSyscall => self.syscall,
            EffectProvenance::Unknown => self.unknown,
        }
    }

    #[must_use]
    pub const fn conditional_effects(self) -> HardEffects {
        self.conditional
    }

    #[must_use]
    pub const fn is_conditional(self, effect: HardEffect) -> bool {
        self.conditional.contains(effect)
    }

    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.effects().contains(HardEffect::Unmodelled)
    }

    #[must_use]
    pub const fn is_effect_free(self) -> bool {
        self.effects().is_empty()
    }

    #[must_use]
    pub const fn dialect(self) -> DialectEffect {
        self.dialect
    }

    #[must_use]
    pub const fn lang(self) -> SourceLang {
        self.lang
    }

    #[must_use]
    pub const fn source_encoding(self) -> SourceEncoding {
        self.source_encoding
    }

    #[must_use]
    pub const fn with_source_encoding(mut self, source_encoding: SourceEncoding) -> Self {
        self.source_encoding = source_encoding;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectRowBuilder {
    row: EffectRow,
}

impl EffectRowBuilder {
    #[must_use]
    pub const fn new(lang: SourceLang) -> Self {
        Self {
            row: EffectRow::none(lang),
        }
    }

    #[must_use]
    pub const fn effect(mut self, effect: HardEffect, provenance: EffectProvenance) -> Self {
        if matches!(effect, HardEffect::AtomicReadModifyWrite) {
            self = self.clear(HardEffect::MemoryRead);
            self = self.clear(HardEffect::MemoryWrite);
        } else if matches!(effect, HardEffect::MemoryRead | HardEffect::MemoryWrite)
            && self
                .row
                .effects()
                .contains(HardEffect::AtomicReadModifyWrite)
        {
            return self;
        }
        self = self.clear(effect);
        match provenance {
            EffectProvenance::Encoding => self.row.encoding = self.row.encoding.with(effect),
            EffectProvenance::ResolvedImport => self.row.import = self.row.import.with(effect),
            EffectProvenance::ResolvedSyscall => self.row.syscall = self.row.syscall.with(effect),
            EffectProvenance::Unknown => self.row.unknown = self.row.unknown.with(effect),
        }
        self
    }

    #[must_use]
    pub const fn conditional_effect(
        mut self,
        effect: HardEffect,
        provenance: EffectProvenance,
    ) -> Self {
        self = self.effect(effect, provenance);
        if self.row.effects().contains(effect) {
            self.row.conditional = self.row.conditional.with(effect);
        }
        self
    }

    #[must_use]
    pub fn effects(mut self, effects: HardEffects, provenance: EffectProvenance) -> Self {
        for effect in effects.iter() {
            self = self.effect(effect, provenance);
        }
        self
    }

    #[must_use]
    pub fn conditional_effects(
        mut self,
        effects: HardEffects,
        provenance: EffectProvenance,
    ) -> Self {
        for effect in effects.iter() {
            self = self.conditional_effect(effect, provenance);
        }
        self
    }

    #[must_use]
    pub const fn dialect(mut self, dialect: DialectEffect) -> Self {
        self.row.dialect = dialect;
        self
    }

    #[must_use]
    pub const fn source_encoding(mut self, source_encoding: SourceEncoding) -> Self {
        self.row.source_encoding = source_encoding;
        self
    }

    #[must_use]
    pub const fn has(&self, effect: HardEffect) -> bool {
        self.row.effects().contains(effect)
    }

    #[must_use]
    pub const fn build(self) -> EffectRow {
        self.row
    }

    const fn clear(mut self, effect: HardEffect) -> Self {
        self.row.encoding = self.row.encoding.without(effect);
        self.row.import = self.row.import.without(effect);
        self.row.syscall = self.row.syscall.without(effect);
        self.row.unknown = self.row.unknown.without(effect);
        self.row.conditional = self.row.conditional.without(effect);
        self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BehaviorKind {
    FileAccess,
    NetworkAccess,
    ProcessCreation,
    RegistryAccess,
    CryptographicUse,
    DynamicCodeLoading,
    PersistenceChange,
    CredentialAccess,
    ClipboardAccess,
    ScreenCapture,
    InputCapture,
    EnvironmentQuery,
    TimeQuery,
    InterProcessCommunication,
}

impl BehaviorKind {
    pub const ALL: [Self; 14] = [
        Self::FileAccess,
        Self::NetworkAccess,
        Self::ProcessCreation,
        Self::RegistryAccess,
        Self::CryptographicUse,
        Self::DynamicCodeLoading,
        Self::PersistenceChange,
        Self::CredentialAccess,
        Self::ClipboardAccess,
        Self::ScreenCapture,
        Self::InputCapture,
        Self::EnvironmentQuery,
        Self::TimeQuery,
        Self::InterProcessCommunication,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FileAccess => "file-access",
            Self::NetworkAccess => "network-access",
            Self::ProcessCreation => "process-creation",
            Self::RegistryAccess => "registry-access",
            Self::CryptographicUse => "cryptographic-use",
            Self::DynamicCodeLoading => "dynamic-code-loading",
            Self::PersistenceChange => "persistence-change",
            Self::CredentialAccess => "credential-access",
            Self::ClipboardAccess => "clipboard-access",
            Self::ScreenCapture => "screen-capture",
            Self::InputCapture => "input-capture",
            Self::EnvironmentQuery => "environment-query",
            Self::TimeQuery => "time-query",
            Self::InterProcessCommunication => "inter-process-communication",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BehaviorAnnotation {
    kind: BehaviorKind,
    tier: ConfidenceTier,
}

impl BehaviorAnnotation {
    #[must_use]
    pub const fn new(kind: BehaviorKind, tier: ConfidenceTier) -> Self {
        Self { kind, tier }
    }

    #[must_use]
    pub const fn kind(self) -> BehaviorKind {
        self.kind
    }

    #[must_use]
    pub const fn tier(self) -> ConfidenceTier {
        self.tier
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct BehaviorAnnotations {
    entries: Vec<BehaviorAnnotation>,
}

impl BehaviorAnnotations {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, annotation: BehaviorAnnotation) {
        match self
            .entries
            .binary_search_by_key(&annotation.kind, |entry: &BehaviorAnnotation| entry.kind)
        {
            Ok(position) => {
                if let Some(existing) = self.entries.get_mut(position)
                    && annotation.tier > existing.tier
                {
                    *existing = annotation;
                }
            }
            Err(position) => self.entries.insert(position, annotation),
        }
    }

    #[must_use]
    pub fn tier_of(&self, kind: BehaviorKind) -> Option<ConfidenceTier> {
        self.entries
            .binary_search_by_key(&kind, |entry: &BehaviorAnnotation| entry.kind)
            .ok()
            .and_then(|position: usize| self.entries.get(position))
            .map(|entry: &BehaviorAnnotation| entry.tier)
    }

    #[must_use]
    pub fn contains(&self, kind: BehaviorKind) -> bool {
        self.tier_of(kind).is_some()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn as_slice(&self) -> &[BehaviorAnnotation] {
        self.entries.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EffectContextError {
    #[error("effect model table exceeds the {limit} model limit")]
    ModelLimit { limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportKey(String);

impl ImportKey {
    #[must_use]
    pub fn new(symbol: impl Into<String>) -> Self {
        Self(symbol.into())
    }

    #[must_use]
    pub fn symbol(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallOtherKey(String);

impl CallOtherKey {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEffectModel {
    effects: HardEffects,
    conditional: HardEffects,
    behaviors: BehaviorAnnotations,
}

impl ImportEffectModel {
    #[must_use]
    pub const fn new(effects: HardEffects) -> Self {
        Self {
            effects,
            conditional: HardEffects::empty(),
            behaviors: BehaviorAnnotations::new(),
        }
    }

    #[must_use]
    pub const fn with_conditional(mut self, conditional: HardEffects) -> Self {
        self.conditional = conditional;
        self
    }

    #[must_use]
    pub fn with_behavior(mut self, annotation: BehaviorAnnotation) -> Self {
        self.behaviors.insert(annotation);
        self
    }

    #[must_use]
    pub const fn effects(&self) -> HardEffects {
        self.effects
    }

    #[must_use]
    pub const fn conditional(&self) -> HardEffects {
        self.conditional
    }

    #[must_use]
    pub const fn behaviors(&self) -> &BehaviorAnnotations {
        &self.behaviors
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallOtherModel {
    effects: HardEffects,
    conditional: HardEffects,
    dialect: NativeEffect,
}

impl CallOtherModel {
    #[must_use]
    pub const fn new(effects: HardEffects, dialect: NativeEffect) -> Self {
        Self {
            effects,
            conditional: HardEffects::empty(),
            dialect,
        }
    }

    #[must_use]
    pub const fn with_conditional(mut self, conditional: HardEffects) -> Self {
        self.conditional = conditional;
        self
    }

    #[must_use]
    pub const fn effects(self) -> HardEffects {
        self.effects
    }

    #[must_use]
    pub const fn conditional(self) -> HardEffects {
        self.conditional
    }

    #[must_use]
    pub const fn dialect(self) -> NativeEffect {
        self.dialect
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallResolution {
    Number(u32),
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallSite {
    resolution: SyscallResolution,
    effects: HardEffects,
}

impl SyscallSite {
    #[must_use]
    pub const fn new(resolution: SyscallResolution, effects: HardEffects) -> Self {
        Self {
            resolution,
            effects,
        }
    }

    #[must_use]
    pub const fn resolution(self) -> SyscallResolution {
        self.resolution
    }

    #[must_use]
    pub const fn effects(self) -> HardEffects {
        self.effects
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectContext {
    imports: BTreeMap<ImportKey, ImportEffectModel>,
    call_others: BTreeMap<CallOtherKey, CallOtherModel>,
    syscalls: BTreeMap<u64, SyscallSite>,
}

impl EffectContext {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            imports: BTreeMap::new(),
            call_others: BTreeMap::new(),
            syscalls: BTreeMap::new(),
        }
    }

    pub fn insert_import(
        &mut self,
        key: ImportKey,
        model: ImportEffectModel,
    ) -> Result<(), EffectContextError> {
        if self.imports.len() >= MAX_EFFECT_MODELS && !self.imports.contains_key(&key) {
            return Err(EffectContextError::ModelLimit {
                limit: MAX_EFFECT_MODELS,
            });
        }
        self.imports.insert(key, model);
        Ok(())
    }

    pub fn insert_call_other(
        &mut self,
        key: CallOtherKey,
        model: CallOtherModel,
    ) -> Result<(), EffectContextError> {
        if self.call_others.len() >= MAX_EFFECT_MODELS && !self.call_others.contains_key(&key) {
            return Err(EffectContextError::ModelLimit {
                limit: MAX_EFFECT_MODELS,
            });
        }
        self.call_others.insert(key, model);
        Ok(())
    }

    pub fn insert_syscall(
        &mut self,
        address: u64,
        site: SyscallSite,
    ) -> Result<(), EffectContextError> {
        if self.syscalls.len() >= MAX_EFFECT_MODELS && !self.syscalls.contains_key(&address) {
            return Err(EffectContextError::ModelLimit {
                limit: MAX_EFFECT_MODELS,
            });
        }
        self.syscalls.insert(address, site);
        Ok(())
    }

    #[must_use]
    pub fn import(&self, symbol: &str) -> Option<&ImportEffectModel> {
        self.imports.get(&ImportKey::new(symbol))
    }

    #[must_use]
    pub fn call_other(&self, name: &str) -> Option<CallOtherModel> {
        self.call_others.get(&CallOtherKey::new(name)).copied()
    }

    #[must_use]
    pub fn syscall_at(&self, address: u64) -> Option<SyscallSite> {
        self.syscalls.get(&address).copied()
    }
}

const X86_FLAG_REGISTERS: [&str; 9] = ["cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of"];
const ARM_FLAG_REGISTERS: [&str; 4] = ["ng", "zr", "cy", "ov"];
const STACK_REGISTERS: [&str; 4] = ["rsp", "rbp", "x29", "fp"];

fn is_flag_register(name: &str) -> bool {
    X86_FLAG_REGISTERS.contains(&name) || ARM_FLAG_REGISTERS.contains(&name)
}

fn is_stack_register(name: &str) -> bool {
    STACK_REGISTERS.contains(&name)
}

fn cell_touches_stack(cell: &str) -> bool {
    cell.split(|byte: char| !byte.is_ascii_alphanumeric())
        .any(is_stack_register)
}

#[must_use]
pub fn derive_effect_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    match instr.source.lang {
        SourceLang::NativeX86 | SourceLang::NativeArm | SourceLang::NativeMips => {
            native_row(instr, context)
        }
        SourceLang::Cil => cil_row(instr, context),
        SourceLang::Jvm => jvm_row(instr, context),
        SourceLang::Dalvik => dalvik_row(instr, context),
        SourceLang::Wasm => wasm_row(instr, context),
        SourceLang::Avm2 => avm2_row(instr, context),
        SourceLang::Beam => beam_row(instr, context),
        SourceLang::Lua => lua_row(instr, context),
        SourceLang::Python => python_row(instr, context),
        SourceLang::Yarv => yarv_row(instr, context),
        SourceLang::Unknown => EffectRow::unknown(SourceLang::Unknown),
    }
}

#[must_use]
pub fn derive_behaviors(instr: &NirInstr, context: &EffectContext) -> BehaviorAnnotations {
    match &instr.op {
        NirOp::ExternCall { symbol } => context
            .import(symbol)
            .map_or_else(BehaviorAnnotations::new, |model: &ImportEffectModel| {
                model.behaviors().clone()
            }),
        _ => BehaviorAnnotations::new(),
    }
}

const fn lifted_memory_facts(instr: &NirInstr, builder: EffectRowBuilder) -> EffectRowBuilder {
    let mut builder: EffectRowBuilder = builder;
    if instr.reads_memory {
        builder = builder.effect(HardEffect::MemoryRead, EffectProvenance::Encoding);
    }
    if instr.writes_memory {
        builder = builder.effect(HardEffect::MemoryWrite, EffectProvenance::Encoding);
    }
    builder
}

fn native_def_use_facts(instr: &NirInstr, builder: EffectRowBuilder) -> EffectRowBuilder {
    let usage: DefUse = def_use(instr);
    let mut builder: EffectRowBuilder = builder;
    for value in &usage.defs {
        builder = match value {
            ValueId::Register(name) => {
                if is_flag_register(name) {
                    builder.effect(HardEffect::FlagWrite, EffectProvenance::Encoding)
                } else if is_stack_register(name) {
                    builder
                        .effect(HardEffect::RegisterWrite, EffectProvenance::Encoding)
                        .effect(HardEffect::StackWrite, EffectProvenance::Encoding)
                } else {
                    builder.effect(HardEffect::RegisterWrite, EffectProvenance::Encoding)
                }
            }
            ValueId::Memory(cell) => {
                if cell_touches_stack(cell) {
                    builder.effect(HardEffect::StackWrite, EffectProvenance::Encoding)
                } else {
                    builder.effect(HardEffect::MemoryWrite, EffectProvenance::Encoding)
                }
            }
            ValueId::Stack(_) => builder.effect(HardEffect::StackWrite, EffectProvenance::Encoding),
        };
    }
    for value in &usage.uses {
        builder = match value {
            ValueId::Register(name) => {
                if is_stack_register(name) {
                    builder
                        .effect(HardEffect::RegisterRead, EffectProvenance::Encoding)
                        .effect(HardEffect::StackRead, EffectProvenance::Encoding)
                } else {
                    builder.effect(HardEffect::RegisterRead, EffectProvenance::Encoding)
                }
            }
            ValueId::Memory(cell) => {
                if cell_touches_stack(cell) {
                    builder.effect(HardEffect::StackRead, EffectProvenance::Encoding)
                } else {
                    builder.effect(HardEffect::MemoryRead, EffectProvenance::Encoding)
                }
            }
            ValueId::Stack(_) => builder.effect(HardEffect::StackRead, EffectProvenance::Encoding),
        };
    }
    builder
}

fn import_call(
    builder: EffectRowBuilder,
    symbol: &str,
    context: &EffectContext,
) -> EffectRowBuilder {
    let builder: EffectRowBuilder =
        builder.effect(HardEffect::ImportCall, EffectProvenance::Encoding);
    context.import(symbol).map_or_else(
        || builder.effect(HardEffect::Unmodelled, EffectProvenance::Unknown),
        |model: &ImportEffectModel| {
            builder
                .effects(
                    model.effects().difference(model.conditional()),
                    EffectProvenance::ResolvedImport,
                )
                .conditional_effects(model.conditional(), EffectProvenance::ResolvedImport)
        },
    )
}

fn native_syscall(
    builder: EffectRowBuilder,
    address: u64,
    context: &EffectContext,
) -> EffectRowBuilder {
    let builder: EffectRowBuilder = builder.effect(HardEffect::Syscall, EffectProvenance::Encoding);
    context.syscall_at(address).map_or_else(
        || {
            builder
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
                .dialect(DialectEffect::Native(NativeEffect::Syscall(
                    SyscallNumber::Unresolved,
                )))
        },
        |site: SyscallSite| match site.resolution() {
            SyscallResolution::Ambiguous => builder
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
                .dialect(DialectEffect::Native(NativeEffect::Syscall(
                    SyscallNumber::ArchitectureAmbiguous,
                ))),
            SyscallResolution::Number(number) => builder
                .effects(site.effects(), EffectProvenance::ResolvedSyscall)
                .dialect(DialectEffect::Native(NativeEffect::Syscall(
                    SyscallNumber::Resolved(number),
                ))),
        },
    )
}

fn native_call_other(
    builder: EffectRowBuilder,
    effect: &CallOtherEffect,
    context: &EffectContext,
) -> EffectRowBuilder {
    context.call_other(&effect.name).map_or_else(
        || {
            let mut builder: EffectRowBuilder = builder;
            if effect.reads_memory {
                builder = builder.effect(HardEffect::MemoryRead, EffectProvenance::Encoding);
            }
            if effect.writes_memory {
                builder = builder.effect(HardEffect::MemoryWrite, EffectProvenance::Encoding);
            }
            builder
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
                .dialect(DialectEffect::Native(NativeEffect::UserOperation))
        },
        |model: CallOtherModel| {
            builder
                .effects(
                    model.effects().difference(model.conditional()),
                    EffectProvenance::Encoding,
                )
                .conditional_effects(model.conditional(), EffectProvenance::Encoding)
                .dialect(DialectEffect::Native(model.dialect()))
        },
    )
}

const fn native_link_effect(lang: SourceLang) -> HardEffect {
    match lang {
        SourceLang::NativeArm | SourceLang::NativeMips => HardEffect::RegisterWrite,
        _ => HardEffect::StackWrite,
    }
}

const fn native_unlink_effect(lang: SourceLang) -> HardEffect {
    match lang {
        SourceLang::NativeArm | SourceLang::NativeMips => HardEffect::RegisterRead,
        _ => HardEffect::StackRead,
    }
}

fn native_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    let lang: SourceLang = instr.source.lang;
    let builder: EffectRowBuilder = EffectRowBuilder::new(lang);
    let builder: EffectRowBuilder = native_def_use_facts(instr, builder);
    let builder: EffectRowBuilder = lifted_memory_facts(instr, builder);
    let builder: EffectRowBuilder = match &instr.op {
        NirOp::Load | NirOp::RawLoad { .. } => builder
            .effect(HardEffect::MemoryRead, EffectProvenance::Encoding)
            .dialect(DialectEffect::Native(NativeEffect::MemoryLoad)),
        NirOp::Store | NirOp::RawStore { .. } => builder
            .effect(HardEffect::MemoryWrite, EffectProvenance::Encoding)
            .dialect(DialectEffect::Native(NativeEffect::MemoryStore)),
        NirOp::Call { target: Some(_) } => builder
            .effect(native_link_effect(lang), EffectProvenance::Encoding)
            .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
            .dialect(DialectEffect::Native(NativeEffect::DirectCall)),
        NirOp::Call { target: None } | NirOp::IndirectCall => builder
            .effect(native_link_effect(lang), EffectProvenance::Encoding)
            .effect(HardEffect::IndirectCall, EffectProvenance::Encoding)
            .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
            .dialect(DialectEffect::Native(NativeEffect::IndirectCall)),
        NirOp::NoReturnCall { target } => {
            let builder: EffectRowBuilder = builder
                .effect(native_link_effect(lang), EffectProvenance::Encoding)
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
                .dialect(DialectEffect::Native(NativeEffect::NoReturnCall));
            if target.is_none() {
                builder.effect(HardEffect::IndirectCall, EffectProvenance::Encoding)
            } else {
                builder
            }
        }
        NirOp::TailCall { target } => {
            let builder: EffectRowBuilder = builder
                .effect(HardEffect::Return, EffectProvenance::Encoding)
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
                .dialect(DialectEffect::Native(NativeEffect::TailCall));
            if target.is_none() {
                builder.effect(HardEffect::IndirectCall, EffectProvenance::Encoding)
            } else {
                builder
            }
        }
        NirOp::ExternCall { symbol } => import_call(builder, symbol, context)
            .dialect(DialectEffect::Native(NativeEffect::ImportCall)),
        NirOp::Return => builder
            .effect(HardEffect::Return, EffectProvenance::Encoding)
            .effect(native_unlink_effect(lang), EffectProvenance::Encoding)
            .dialect(DialectEffect::Native(NativeEffect::Return)),
        NirOp::Branch { target: None } => builder
            .effect(HardEffect::IndirectJump, EffectProvenance::Encoding)
            .dialect(DialectEffect::Native(NativeEffect::IndirectJump)),
        NirOp::CondBranch { target: None } => builder
            .conditional_effect(HardEffect::IndirectJump, EffectProvenance::Encoding)
            .dialect(DialectEffect::Native(NativeEffect::IndirectJump)),
        NirOp::Branch { .. } | NirOp::CondBranch { .. } | NirOp::Nop | NirOp::Phi => builder,
        NirOp::Interrupt => native_syscall(builder, instr.address, context),
        NirOp::Unmodeled { .. } => builder
            .effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
            .dialect(DialectEffect::Native(NativeEffect::Unmodelled)),
        NirOp::CallOther { effect } => native_call_other(builder, effect, context),
        NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Copy { .. }
        | NirOp::Subpiece { .. }
        | NirOp::Deposit { .. }
        | NirOp::Piece { .. }
        | NirOp::Value { .. } => {
            if builder.has(HardEffect::FlagWrite) {
                builder.dialect(DialectEffect::Native(NativeEffect::FlagUpdate))
            } else if builder.has(HardEffect::RegisterWrite) {
                builder.dialect(DialectEffect::Native(NativeEffect::RegisterTransfer))
            } else {
                builder
            }
        }
    };
    builder.build()
}

fn split_once_exact(mnemonic: &str, separator: char) -> (&str, &str) {
    mnemonic
        .split_once(separator)
        .map_or((mnemonic, ""), |(head, tail): (&str, &str)| (head, tail))
}

fn cil_dialect(mnemonic: &str) -> Option<(CilEffect, HardEffects)> {
    const ELEMENT_TYPES: [&str; 12] = [
        "", "i", "i1", "u1", "i2", "u2", "i4", "u4", "i8", "r4", "r8", "ref",
    ];
    let (head, tail): (&str, &str) = split_once_exact(mnemonic, '.');
    let typed: bool = ELEMENT_TYPES.contains(&tail);
    match (head, tail) {
        ("newobj", "") => Some((
            CilEffect::NewObject,
            HardEffects::of(HardEffect::MemoryWrite).with(HardEffect::Unmodelled),
        )),
        ("newarr", "") => Some((
            CilEffect::NewArray,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("box", "") => Some((CilEffect::Box, HardEffects::of(HardEffect::MemoryWrite))),
        ("unbox", "" | "any") => Some((CilEffect::Unbox, HardEffects::of(HardEffect::MemoryRead))),
        ("ldfld", "") => Some((
            CilEffect::LoadField,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("stfld", "") => Some((
            CilEffect::StoreField,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("ldsfld", "") => Some((
            CilEffect::LoadStaticField,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("stsfld", "") => Some((
            CilEffect::StoreStaticField,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("ldelem", _) if typed => Some((
            CilEffect::LoadElement,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("stelem", _) if typed => Some((
            CilEffect::StoreElement,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("ldind", _) if typed => Some((
            CilEffect::LoadIndirect,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("stind", _) if typed => Some((
            CilEffect::StoreIndirect,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("initblk", "") => Some((
            CilEffect::InitBlock,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("cpblk", "") => Some((
            CilEffect::CopyBlock,
            HardEffects::of(HardEffect::MemoryRead).with(HardEffect::MemoryWrite),
        )),
        ("localloc", "") => Some((
            CilEffect::StackAllocate,
            HardEffects::of(HardEffect::StackWrite),
        )),
        ("call", "") => Some((
            CilEffect::ManagedCall,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("callvirt", "") => Some((
            CilEffect::VirtualCall,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("calli", "") => Some((
            CilEffect::IndirectCall,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        ("throw", "") => Some((
            CilEffect::Throw,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        ("rethrow", "") => Some((
            CilEffect::Rethrow,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        ("endfinally", "") => Some((
            CilEffect::EndFinally,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        ("endfilter", "") => Some((
            CilEffect::EndFilter,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        ("leave", "" | "s") => Some((CilEffect::LeaveRegion, HardEffects::empty())),
        ("volatile", "") => Some((
            CilEffect::VolatileAccess,
            HardEffects::of(HardEffect::MemoryFence),
        )),
        ("ret", "") => Some((CilEffect::Return, HardEffects::of(HardEffect::Return))),
        _ => None,
    }
}

fn jvm_dialect(mnemonic: &str) -> Option<(JvmEffect, HardEffects)> {
    const ARRAY_LOADS: [&str; 8] = [
        "iaload", "laload", "faload", "daload", "aaload", "baload", "caload", "saload",
    ];
    const ARRAY_STORES: [&str; 8] = [
        "iastore", "lastore", "fastore", "dastore", "aastore", "bastore", "castore", "sastore",
    ];
    const RETURNS: [&str; 6] = [
        "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return",
    ];
    if ARRAY_LOADS.contains(&mnemonic) {
        return Some((
            JvmEffect::ArrayLoad,
            HardEffects::of(HardEffect::MemoryRead),
        ));
    }
    if ARRAY_STORES.contains(&mnemonic) {
        return Some((
            JvmEffect::ArrayStore,
            HardEffects::of(HardEffect::MemoryWrite),
        ));
    }
    if RETURNS.contains(&mnemonic) {
        return Some((JvmEffect::Return, HardEffects::of(HardEffect::Return)));
    }
    match mnemonic {
        "new" => Some((
            JvmEffect::NewObject,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "newarray" | "anewarray" | "multianewarray" => Some((
            JvmEffect::NewArray,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getfield" => Some((JvmEffect::GetField, HardEffects::of(HardEffect::MemoryRead))),
        "putfield" => Some((
            JvmEffect::PutField,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getstatic" => Some((
            JvmEffect::GetStatic,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "putstatic" => Some((
            JvmEffect::PutStatic,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "invokevirtual" => Some((
            JvmEffect::InvokeVirtual,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "invokestatic" => Some((
            JvmEffect::InvokeStatic,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "invokespecial" => Some((
            JvmEffect::InvokeSpecial,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "invokeinterface" => Some((
            JvmEffect::InvokeInterface,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "invokedynamic" => Some((
            JvmEffect::InvokeDynamic,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        "athrow" => Some((
            JvmEffect::AThrow,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        "monitorenter" => Some((
            JvmEffect::MonitorEnter,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        "monitorexit" => Some((
            JvmEffect::MonitorExit,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        _ => None,
    }
}

fn dalvik_dialect(mnemonic: &str) -> Option<(DalvikEffect, HardEffects)> {
    let ranged: &str = mnemonic.strip_suffix("/range").unwrap_or(mnemonic);
    let dequicked: &str = ranged.strip_suffix("-quick").unwrap_or(ranged);
    dequicked.strip_suffix("-volatile").map_or_else(
        || dalvik_base_dialect(dequicked),
        |base: &str| {
            dalvik_base_dialect(base).map(|(dialect, effects): (DalvikEffect, HardEffects)| {
                (dialect, effects.with(HardEffect::MemoryFence))
            })
        },
    )
}

fn dalvik_base_dialect(base: &str) -> Option<(DalvikEffect, HardEffects)> {
    const VALUE_SUFFIXES: [&str; 8] = [
        "", "wide", "object", "boolean", "byte", "char", "short", "void",
    ];
    let (head, tail): (&str, &str) = split_once_exact(base, '-');
    let typed: bool = VALUE_SUFFIXES.contains(&tail);
    match (head, tail) {
        ("new", "instance") => Some((
            DalvikEffect::NewInstance,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("new", "array") | ("filled", "new-array") => Some((
            DalvikEffect::NewArray,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("iget", _) if typed => Some((
            DalvikEffect::InstanceGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("iput", _) if typed => Some((
            DalvikEffect::InstancePut,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("sget", _) if typed => Some((
            DalvikEffect::StaticGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("sput", _) if typed => Some((
            DalvikEffect::StaticPut,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("aget", _) if typed => Some((
            DalvikEffect::ArrayGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("aput", _) if typed => Some((
            DalvikEffect::ArrayPut,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("invoke", "virtual") => Some((
            DalvikEffect::InvokeVirtual,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("invoke", "super") => Some((
            DalvikEffect::InvokeSuper,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("invoke", "direct") => Some((
            DalvikEffect::InvokeDirect,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("invoke", "static") => Some((
            DalvikEffect::InvokeStatic,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("invoke", "interface") => Some((
            DalvikEffect::InvokeInterface,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        ("invoke", "polymorphic" | "custom") => Some((
            DalvikEffect::InvokePolymorphic,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        ("throw", "" | "verification-error") => Some((
            DalvikEffect::Throw,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        ("move", "exception") => Some((
            DalvikEffect::MoveException,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        ("monitor", "enter") => Some((
            DalvikEffect::MonitorEnter,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        ("monitor", "exit") => Some((
            DalvikEffect::MonitorExit,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        ("return", _) if typed => Some((DalvikEffect::Return, HardEffects::of(HardEffect::Return))),
        _ => None,
    }
}

fn wasm_dialect(mnemonic: &str) -> Option<(WasmEffect, HardEffects)> {
    const NUMERIC_TYPES: [&str; 5] = ["i32", "i64", "f32", "f64", "v128"];
    const LOAD_FORMS: [&str; 9] = [
        "load",
        "load8_s",
        "load8_u",
        "load16_s",
        "load16_u",
        "load32_s",
        "load32_u",
        "load8x8_s",
        "load8x8_u",
    ];
    const STORE_FORMS: [&str; 5] = ["store", "store8", "store16", "store32", "store64"];
    const FLAT_LOADS: [&str; 14] = [
        "i32load",
        "i64load",
        "f32load",
        "f64load",
        "i32load8s",
        "i32load8u",
        "i32load16s",
        "i32load16u",
        "i64load8s",
        "i64load8u",
        "i64load16s",
        "i64load16u",
        "i64load32s",
        "i64load32u",
    ];
    const FLAT_STORES: [&str; 9] = [
        "i32store",
        "i64store",
        "f32store",
        "f64store",
        "i32store8",
        "i32store16",
        "i64store8",
        "i64store16",
        "i64store32",
    ];
    if FLAT_LOADS.contains(&mnemonic) {
        return Some((
            WasmEffect::LinearMemoryLoad,
            HardEffects::of(HardEffect::MemoryRead),
        ));
    }
    if FLAT_STORES.contains(&mnemonic) {
        return Some((
            WasmEffect::LinearMemoryStore,
            HardEffects::of(HardEffect::MemoryWrite),
        ));
    }
    let (head, tail): (&str, &str) = split_once_exact(mnemonic, '.');
    if NUMERIC_TYPES.contains(&head) {
        if LOAD_FORMS.contains(&tail) {
            return Some((
                WasmEffect::LinearMemoryLoad,
                HardEffects::of(HardEffect::MemoryRead),
            ));
        }
        if STORE_FORMS.contains(&tail) {
            return Some((
                WasmEffect::LinearMemoryStore,
                HardEffects::of(HardEffect::MemoryWrite),
            ));
        }
    }
    match (head, tail) {
        ("memory", "grow") | ("memorygrow", "") => Some((
            WasmEffect::MemoryGrow,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("memory", "size") | ("memorysize", "") => {
            Some((WasmEffect::MemorySize, HardEffects::empty()))
        }
        ("memory", "copy") | ("memorycopy", "") => Some((
            WasmEffect::MemoryCopy,
            HardEffects::of(HardEffect::MemoryRead).with(HardEffect::MemoryWrite),
        )),
        ("memory", "fill") | ("memoryfill", "") => Some((
            WasmEffect::MemoryFill,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("memory", "init") | ("memoryinit", "") => Some((
            WasmEffect::MemoryInit,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("table", "get") | ("tableget", "") => Some((
            WasmEffect::TableGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("table", "set") | ("tableset", "") => Some((
            WasmEffect::TableSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("global", "get") | ("globalget", "") => Some((
            WasmEffect::GlobalGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        ("global", "set") | ("globalset", "") => Some((
            WasmEffect::GlobalSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        ("atomic", "fence") | ("atomicfence", "") => {
            Some((WasmEffect::Fence, HardEffects::of(HardEffect::MemoryFence)))
        }
        ("memory", "atomic.wait32" | "atomic.wait64")
        | ("memoryatomicwait32" | "memoryatomicwait64", "") => Some((
            WasmEffect::AtomicWait,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        ("memory", "atomic.notify") | ("memoryatomicnotify", "") => Some((
            WasmEffect::AtomicNotify,
            HardEffects::of(HardEffect::AtomicReadModifyWrite),
        )),
        ("call", "") => Some((WasmEffect::Call, HardEffects::of(HardEffect::Unmodelled))),
        ("call_indirect" | "return_call_indirect", "") => Some((
            WasmEffect::CallIndirect,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        ("call_ref" | "return_call_ref", "") => Some((
            WasmEffect::CallRef,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        ("throw" | "throw_ref" | "rethrow", "") => Some((
            WasmEffect::Throw,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        ("catch" | "catch_all" | "catchall" | "delegate", "") => Some((
            WasmEffect::Catch,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        ("return", "") => Some((WasmEffect::Return, HardEffects::of(HardEffect::Return))),
        ("unreachable", "") => Some((
            WasmEffect::Unreachable,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        _ => None,
    }
}

fn avm2_dialect(mnemonic: &str) -> Option<(Avm2Effect, HardEffects)> {
    match mnemonic {
        "getproperty" | "getsuper" | "getdescendants" => Some((
            Avm2Effect::GetProperty,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setproperty" | "initproperty" | "setsuper" => Some((
            Avm2Effect::SetProperty,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "deleteproperty" => Some((
            Avm2Effect::DeleteProperty,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getslot" => Some((Avm2Effect::GetSlot, HardEffects::of(HardEffect::MemoryRead))),
        "setslot" => Some((
            Avm2Effect::SetSlot,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getglobalslot" => Some((
            Avm2Effect::GetGlobalSlot,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setglobalslot" => Some((
            Avm2Effect::SetGlobalSlot,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "construct" | "newobject" | "newarray" | "newclass" | "newfunction" => Some((
            Avm2Effect::ConstructObject,
            HardEffects::of(HardEffect::MemoryWrite).with(HardEffect::Unmodelled),
        )),
        "constructprop" => Some((
            Avm2Effect::ConstructProperty,
            HardEffects::of(HardEffect::MemoryWrite).with(HardEffect::Unmodelled),
        )),
        "constructsuper" => Some((
            Avm2Effect::ConstructSuper,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "callproperty" | "callpropvoid" | "callproplex" => Some((
            Avm2Effect::CallProperty,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "callmethod" | "callstatic" | "call" => Some((
            Avm2Effect::CallMethod,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "callsuper" | "callsupervoid" => Some((
            Avm2Effect::CallSuper,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "throw" => Some((
            Avm2Effect::Throw,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        "returnvalue" | "returnvoid" => {
            Some((Avm2Effect::Return, HardEffects::of(HardEffect::Return)))
        }
        _ => None,
    }
}

fn beam_dialect(mnemonic: &str) -> Option<(BeamEffect, HardEffects)> {
    const BIFS: [&str; 8] = [
        "bif0",
        "bif1",
        "bif2",
        "gc_bif1",
        "gc_bif2",
        "gc_bif3",
        "call_fun",
        "call_fun2",
    ];
    if BIFS.contains(&mnemonic) {
        return Some((BeamEffect::BifCall, HardEffects::of(HardEffect::Unmodelled)));
    }
    match mnemonic {
        "call" | "call_only" | "call_last" => Some((
            BeamEffect::LocalCall,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "call_ext" | "call_ext_only" | "call_ext_last" => Some((
            BeamEffect::ExternalCall,
            HardEffects::of(HardEffect::ImportCall).with(HardEffect::Unmodelled),
        )),
        "apply" | "apply_last" => Some((
            BeamEffect::ApplyCall,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        "send" => Some((BeamEffect::Send, HardEffects::of(HardEffect::Unmodelled))),
        "loop_rec" | "wait" | "wait_timeout" => {
            Some((BeamEffect::Receive, HardEffects::of(HardEffect::Unmodelled)))
        }
        "allocate" | "allocate_heap" | "allocate_zero" | "test_heap" => Some((
            BeamEffect::HeapAllocate,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "get_tuple_element"
        | "get_list"
        | "get_hd"
        | "get_tl"
        | "get_map_elements"
        | "get_record_field"
        | "get_record_elements" => Some((
            BeamEffect::TupleGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "set_tuple_element" | "update_record" | "put_tuple2" => Some((
            BeamEffect::TupleSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "raise" | "badmatch" | "if_end" | "case_end" => Some((
            BeamEffect::Raise,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        "try" | "catch" => Some((
            BeamEffect::EnterProtectedRegion,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        "try_case" | "try_end" | "catch_end" => Some((
            BeamEffect::LeaveProtectedRegion,
            HardEffects::of(HardEffect::ExceptionCatch),
        )),
        "return" => Some((BeamEffect::Return, HardEffects::of(HardEffect::Return))),
        _ => None,
    }
}

fn lua_dialect(mnemonic: &str) -> Option<(LuaEffect, HardEffects)> {
    match mnemonic {
        "GETTABLE" | "GETFIELD" | "GETI" | "SELF" | "GETTABUP" => {
            Some((LuaEffect::TableGet, HardEffects::of(HardEffect::MemoryRead)))
        }
        "SETTABLE" | "SETFIELD" | "SETI" | "SETLIST" | "SETTABUP" => Some((
            LuaEffect::TableSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "GETUPVAL" => Some((
            LuaEffect::UpvalueGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "SETUPVAL" => Some((
            LuaEffect::UpvalueSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "GETGLOBAL" => Some((
            LuaEffect::GlobalGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "SETGLOBAL" => Some((
            LuaEffect::GlobalSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "NEWTABLE" => Some((
            LuaEffect::NewTable,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "CLOSURE" => Some((LuaEffect::Closure, HardEffects::of(HardEffect::MemoryWrite))),
        "CALL" | "CALLM" => Some((LuaEffect::Call, HardEffects::of(HardEffect::Unmodelled))),
        "TAILCALL" | "CALLT" | "CALLMT" => Some((
            LuaEffect::TailCall,
            HardEffects::of(HardEffect::Return).with(HardEffect::Unmodelled),
        )),
        "RETURN" | "RETURN0" | "RETURN1" | "RET" | "RET0" | "RET1" | "RETM" => {
            Some((LuaEffect::Return, HardEffects::of(HardEffect::Return)))
        }
        _ => None,
    }
}

fn python_dialect(mnemonic: &str) -> Option<(PythonEffect, HardEffects)> {
    match mnemonic {
        "load" => Some((
            PythonEffect::LoadSubscript,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "store" => Some((
            PythonEffect::StoreSubscript,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "call" => Some((PythonEffect::Call, HardEffects::of(HardEffect::Unmodelled))),
        "raise" => Some((
            PythonEffect::RaiseException,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        "return" => Some((PythonEffect::Return, HardEffects::of(HardEffect::Return))),
        _ => None,
    }
}

fn yarv_dialect(mnemonic: &str) -> Option<(YarvEffect, HardEffects)> {
    match mnemonic {
        "getinstancevariable" => Some((
            YarvEffect::InstanceVariableGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setinstancevariable" => Some((
            YarvEffect::InstanceVariableSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getglobal" => Some((
            YarvEffect::GlobalGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setglobal" => Some((
            YarvEffect::GlobalSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getclassvariable" => Some((
            YarvEffect::ClassVariableGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setclassvariable" => Some((
            YarvEffect::ClassVariableSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "getconstant" | "opt_getconstant_path" => Some((
            YarvEffect::ConstantGet,
            HardEffects::of(HardEffect::MemoryRead),
        )),
        "setconstant" => Some((
            YarvEffect::ConstantSet,
            HardEffects::of(HardEffect::MemoryWrite),
        )),
        "send" | "opt_send_without_block" => {
            Some((YarvEffect::Send, HardEffects::of(HardEffect::Unmodelled)))
        }
        "invokesuper" => Some((
            YarvEffect::InvokeSuper,
            HardEffects::of(HardEffect::Unmodelled),
        )),
        "invokeblock" => Some((
            YarvEffect::InvokeBlock,
            HardEffects::of(HardEffect::IndirectCall).with(HardEffect::Unmodelled),
        )),
        "invokebuiltin" | "opt_invokebuiltin_delegate" | "opt_invokebuiltin_delegate_leave" => {
            Some((
                YarvEffect::InvokeBuiltin,
                HardEffects::of(HardEffect::Unmodelled),
            ))
        }
        "throw" => Some((
            YarvEffect::Throw,
            HardEffects::of(HardEffect::ExceptionRaise),
        )),
        "leave" => Some((YarvEffect::Return, HardEffects::of(HardEffect::Return))),
        _ => None,
    }
}

fn managed_structural(
    instr: &NirInstr,
    builder: EffectRowBuilder,
    context: &EffectContext,
) -> EffectRowBuilder {
    match &instr.op {
        NirOp::Load | NirOp::RawLoad { .. } => {
            builder.effect(HardEffect::MemoryRead, EffectProvenance::Encoding)
        }
        NirOp::Store | NirOp::RawStore { .. } => {
            builder.effect(HardEffect::MemoryWrite, EffectProvenance::Encoding)
        }
        NirOp::Call { target: Some(_) }
        | NirOp::NoReturnCall { target: Some(_) }
        | NirOp::Unmodeled { .. } => {
            builder.effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
        }
        NirOp::Call { target: None }
        | NirOp::NoReturnCall { target: None }
        | NirOp::IndirectCall => builder
            .effect(HardEffect::IndirectCall, EffectProvenance::Encoding)
            .effect(HardEffect::Unmodelled, EffectProvenance::Unknown),
        NirOp::TailCall { target } => {
            let builder: EffectRowBuilder = builder
                .effect(HardEffect::Return, EffectProvenance::Encoding)
                .effect(HardEffect::Unmodelled, EffectProvenance::Unknown);
            if target.is_none() {
                builder.effect(HardEffect::IndirectCall, EffectProvenance::Encoding)
            } else {
                builder
            }
        }
        NirOp::ExternCall { symbol } => import_call(builder, symbol, context),
        NirOp::Return => builder.effect(HardEffect::Return, EffectProvenance::Encoding),
        NirOp::Branch { target: None } => {
            builder.effect(HardEffect::IndirectJump, EffectProvenance::Encoding)
        }
        NirOp::CondBranch { target: None } => {
            builder.conditional_effect(HardEffect::IndirectJump, EffectProvenance::Encoding)
        }
        NirOp::CallOther { effect } => {
            let mut builder: EffectRowBuilder = builder;
            if effect.reads_memory {
                builder = builder.effect(HardEffect::MemoryRead, EffectProvenance::Encoding);
            }
            if effect.writes_memory {
                builder = builder.effect(HardEffect::MemoryWrite, EffectProvenance::Encoding);
            }
            builder.effect(HardEffect::Unmodelled, EffectProvenance::Unknown)
        }
        NirOp::Nop
        | NirOp::Const
        | NirOp::BinOp { .. }
        | NirOp::Phi
        | NirOp::Interrupt
        | NirOp::Branch { .. }
        | NirOp::CondBranch { .. }
        | NirOp::Subpiece { .. }
        | NirOp::Deposit { .. }
        | NirOp::Copy { .. }
        | NirOp::Value { .. }
        | NirOp::Piece { .. } => builder,
    }
}

fn managed_row<Effect: Copy>(
    instr: &NirInstr,
    context: &EffectContext,
    lookup: fn(&str) -> Option<(Effect, HardEffects)>,
    wrap: fn(Effect) -> DialectEffect,
    unmodelled: Effect,
    raise: Option<Effect>,
) -> EffectRow {
    let lang: SourceLang = instr.source.lang;
    let builder: EffectRowBuilder = EffectRowBuilder::new(lang);
    let builder: EffectRowBuilder = lifted_memory_facts(instr, builder);
    let builder: EffectRowBuilder = managed_structural(instr, builder, context);
    match lookup(instr.mnemonic.as_str()) {
        Some((dialect, effects)) => builder
            .effects(effects, EffectProvenance::Encoding)
            .dialect(wrap(dialect))
            .build(),
        None => match (&instr.op, raise) {
            (NirOp::Interrupt, Some(raise_effect)) => builder
                .effect(HardEffect::ExceptionRaise, EffectProvenance::Encoding)
                .dialect(wrap(raise_effect))
                .build(),
            (NirOp::Interrupt, None) => builder
                .effect(HardEffect::ExceptionRaise, EffectProvenance::Encoding)
                .dialect(wrap(unmodelled))
                .build(),
            (NirOp::Unmodeled { .. }, _) => builder.dialect(wrap(unmodelled)).build(),
            _ => builder.build(),
        },
    }
}

fn cil_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        cil_dialect,
        DialectEffect::Cil,
        CilEffect::Unmodelled,
        Some(CilEffect::Throw),
    )
}

fn jvm_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        jvm_dialect,
        DialectEffect::Jvm,
        JvmEffect::Unmodelled,
        Some(JvmEffect::AThrow),
    )
}

fn dalvik_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        dalvik_dialect,
        DialectEffect::Dalvik,
        DalvikEffect::Unmodelled,
        Some(DalvikEffect::Throw),
    )
}

fn wasm_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        wasm_dialect,
        DialectEffect::Wasm,
        WasmEffect::Unmodelled,
        Some(WasmEffect::Throw),
    )
}

fn avm2_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        avm2_dialect,
        DialectEffect::Avm2,
        Avm2Effect::Unmodelled,
        Some(Avm2Effect::Throw),
    )
}

fn beam_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        beam_dialect,
        DialectEffect::Beam,
        BeamEffect::Unmodelled,
        Some(BeamEffect::Raise),
    )
}

fn lua_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        lua_dialect,
        DialectEffect::Lua,
        LuaEffect::Unmodelled,
        None,
    )
}

fn python_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        python_dialect,
        DialectEffect::Python,
        PythonEffect::Unmodelled,
        Some(PythonEffect::RaiseException),
    )
}

fn yarv_row(instr: &NirInstr, context: &EffectContext) -> EffectRow {
    managed_row(
        instr,
        context,
        yarv_dialect,
        DialectEffect::Yarv,
        YarvEffect::Unmodelled,
        Some(YarvEffect::Throw),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EffectTableError {
    #[error("effect row count exceeds the {limit} row limit")]
    RowLimit { limit: usize },
    #[error("cannot allocate effect storage for {requested} rows")]
    Allocation { requested: usize },
    #[error("function or instruction count exceeds the effect index range")]
    IndexOverflow,
    #[error("effect table has no function start index")]
    MissingFunctionStarts,
    #[error("function start index {index} is not ordered")]
    UnorderedFunctionStart { index: usize },
    #[error("effect table declares {declared} rows but carries {rows}")]
    RowCount { declared: u32, rows: usize },
    #[error("effect table function count {rows} does not match module function count {functions}")]
    FunctionCount { rows: usize, functions: usize },
    #[error("function {function_index} carries {rows} effect rows for {instructions} instructions")]
    InstructionCount {
        function_index: u32,
        rows: u32,
        instructions: usize,
    },
    #[error("effect label sequence exceeds the {limit} label limit")]
    EffectLabelLimit { limit: usize },
    #[error("effect row is invalid: {0}")]
    Row(#[from] EffectRowError),
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct EffectTable {
    rows: Vec<EffectRow>,
    function_starts: Vec<u32>,
}

impl EffectTable {
    pub fn for_module(
        module: &NirModule,
        context: &EffectContext,
    ) -> Result<Self, EffectTableError> {
        Self::build(
            module,
            context,
            |_function_index: u32, _instruction_index: u32| -> SourceEncoding {
                SourceEncoding::Unknown
            },
        )
    }

    pub fn for_artifact(
        artifact: &NirArtifact,
        context: &EffectContext,
    ) -> Result<Self, EffectTableError> {
        Self::build(
            artifact.module(),
            context,
            |function_index: u32, instruction_index: u32| -> SourceEncoding {
                artifact
                    .source_unit(function_index, instruction_index)
                    .map_or(SourceEncoding::Unknown, |unit: &SourceUnit| {
                        match unit.bytes() {
                            SourceBytes::Original(_) => SourceEncoding::Present,
                            SourceBytes::Synthesized => SourceEncoding::Synthesized,
                        }
                    })
            },
        )
    }

    fn build(
        module: &NirModule,
        context: &EffectContext,
        source_encoding: impl Fn(u32, u32) -> SourceEncoding,
    ) -> Result<Self, EffectTableError> {
        let total: usize = module
            .functions
            .iter()
            .try_fold(0_usize, |accumulated: usize, function: &NirFunction| {
                accumulated.checked_add(function.instructions.len())
            })
            .ok_or(EffectTableError::IndexOverflow)?;
        if total > MAX_EFFECT_ROWS {
            return Err(EffectTableError::RowLimit {
                limit: MAX_EFFECT_ROWS,
            });
        }
        let function_count: usize = module
            .functions
            .len()
            .checked_add(1)
            .ok_or(EffectTableError::IndexOverflow)?;

        let mut rows: Vec<EffectRow> = Vec::new();
        rows.try_reserve_exact(total)
            .map_err(|_error| EffectTableError::Allocation { requested: total })?;
        let mut function_starts: Vec<u32> = Vec::new();
        function_starts
            .try_reserve_exact(function_count)
            .map_err(|_error| EffectTableError::Allocation {
                requested: function_count,
            })?;

        for (function_ordinal, function) in module.functions.iter().enumerate() {
            let function_index: u32 = u32::try_from(function_ordinal)
                .map_err(|_error| EffectTableError::IndexOverflow)?;
            let start: u32 =
                u32::try_from(rows.len()).map_err(|_error| EffectTableError::IndexOverflow)?;
            function_starts.push(start);
            for (instruction_ordinal, instr) in function.instructions.iter().enumerate() {
                let instruction_index: u32 = u32::try_from(instruction_ordinal)
                    .map_err(|_error| EffectTableError::IndexOverflow)?;
                let row: EffectRow = derive_effect_row(instr, context)
                    .with_source_encoding(source_encoding(function_index, instruction_index));
                row.validate()?;
                rows.push(row);
            }
        }
        let end: u32 =
            u32::try_from(rows.len()).map_err(|_error| EffectTableError::IndexOverflow)?;
        function_starts.push(end);

        Ok(Self {
            rows,
            function_starts,
        })
    }

    pub fn from_parts(
        rows: Vec<EffectRow>,
        function_starts: Vec<u32>,
    ) -> Result<Self, EffectTableError> {
        if rows.len() > MAX_EFFECT_ROWS {
            return Err(EffectTableError::RowLimit {
                limit: MAX_EFFECT_ROWS,
            });
        }
        let Some(first): Option<&u32> = function_starts.first() else {
            return Err(EffectTableError::MissingFunctionStarts);
        };
        if *first != 0 {
            return Err(EffectTableError::UnorderedFunctionStart { index: 0 });
        }
        for index in 1..function_starts.len() {
            let previous: u32 = index
                .checked_sub(1)
                .and_then(|prior: usize| function_starts.get(prior).copied())
                .ok_or(EffectTableError::IndexOverflow)?;
            let current: u32 = function_starts
                .get(index)
                .copied()
                .ok_or(EffectTableError::IndexOverflow)?;
            if current < previous {
                return Err(EffectTableError::UnorderedFunctionStart { index });
            }
        }
        let declared: u32 = function_starts
            .last()
            .copied()
            .ok_or(EffectTableError::MissingFunctionStarts)?;
        if usize::try_from(declared).map_err(|_error| EffectTableError::IndexOverflow)?
            != rows.len()
        {
            return Err(EffectTableError::RowCount {
                declared,
                rows: rows.len(),
            });
        }
        for row in &rows {
            row.validate()?;
        }
        Ok(Self {
            rows,
            function_starts,
        })
    }

    pub fn validate_against(&self, module: &NirModule) -> Result<(), EffectTableError> {
        if self.function_count() != module.functions.len() {
            return Err(EffectTableError::FunctionCount {
                rows: self.function_count(),
                functions: module.functions.len(),
            });
        }
        for (function_ordinal, function) in module.functions.iter().enumerate() {
            let function_index: u32 = u32::try_from(function_ordinal)
                .map_err(|_error| EffectTableError::IndexOverflow)?;
            let rows: &[EffectRow] = self
                .function_rows(function_index)
                .ok_or(EffectTableError::IndexOverflow)?;
            if rows.len() != function.instructions.len() {
                return Err(EffectTableError::InstructionCount {
                    function_index,
                    rows: u32::try_from(rows.len())
                        .map_err(|_error| EffectTableError::IndexOverflow)?,
                    instructions: function.instructions.len(),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn row(&self, function_index: u32, instruction_index: u32) -> Option<EffectRow> {
        self.function_rows(function_index)?
            .get(usize::try_from(instruction_index).ok()?)
            .copied()
    }

    #[must_use]
    pub fn function_rows(&self, function_index: u32) -> Option<&[EffectRow]> {
        let index: usize = usize::try_from(function_index).ok()?;
        let start: usize = usize::try_from(*self.function_starts.get(index)?).ok()?;
        let end: usize = usize::try_from(*self.function_starts.get(index.checked_add(1)?)?).ok()?;
        self.rows.get(start..end)
    }

    #[must_use]
    pub fn rows(&self) -> &[EffectRow] {
        &self.rows
    }

    #[must_use]
    pub fn function_starts(&self) -> &[u32] {
        &self.function_starts
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.function_starts.len().saturating_sub(1)
    }

    #[must_use]
    pub const fn row_byte_size() -> usize {
        size_of::<EffectRow>()
    }

    #[must_use]
    pub const fn byte_size(&self) -> usize {
        self.rows.len() * size_of::<EffectRow>() + self.function_starts.len() * size_of::<u32>()
    }
}

struct BoundedSeqSeed<T> {
    limit: usize,
    marker: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for BoundedSeqSeed<T> {
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedSeqVisitor {
            limit: self.limit,
            marker: PhantomData,
        })
    }
}

struct BoundedSeqVisitor<T> {
    limit: usize,
    marker: PhantomData<T>,
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for BoundedSeqVisitor<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded effect sequence")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let hinted: usize = sequence.size_hint().unwrap_or(0);
        if hinted > self.limit {
            return Err(de::Error::custom(EffectTableError::RowLimit {
                limit: self.limit,
            }));
        }
        let mut items: Vec<T> = Vec::new();
        items.try_reserve_exact(hinted).map_err(de::Error::custom)?;
        while let Some(item) = sequence.next_element::<T>()? {
            if items.len() == self.limit {
                return Err(de::Error::custom(EffectTableError::RowLimit {
                    limit: self.limit,
                }));
            }
            if items.len() == items.capacity() {
                items.try_reserve_exact(1).map_err(de::Error::custom)?;
            }
            items.push(item);
        }
        Ok(items)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum EffectTableField {
    Rows,
    FunctionStarts,
}

struct EffectTableVisitor;

impl<'de> Visitor<'de> for EffectTableVisitor {
    type Value = EffectTable;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a checked effect table")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let rows: Vec<EffectRow> = sequence
            .next_element_seed(BoundedSeqSeed {
                limit: MAX_EFFECT_ROWS,
                marker: PhantomData,
            })?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let function_starts: Vec<u32> = sequence
            .next_element_seed(BoundedSeqSeed {
                limit: MAX_EFFECT_ROWS + 1,
                marker: PhantomData,
            })?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        EffectTable::from_parts(rows, function_starts).map_err(de::Error::custom)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut rows: Option<Vec<EffectRow>> = None;
        let mut function_starts: Option<Vec<u32>> = None;
        while let Some(field) = map.next_key::<EffectTableField>()? {
            match field {
                EffectTableField::Rows => {
                    if rows.is_some() {
                        return Err(de::Error::duplicate_field("rows"));
                    }
                    rows = Some(map.next_value_seed(BoundedSeqSeed {
                        limit: MAX_EFFECT_ROWS,
                        marker: PhantomData,
                    })?);
                }
                EffectTableField::FunctionStarts => {
                    if function_starts.is_some() {
                        return Err(de::Error::duplicate_field("function_starts"));
                    }
                    function_starts = Some(map.next_value_seed(BoundedSeqSeed {
                        limit: MAX_EFFECT_ROWS + 1,
                        marker: PhantomData,
                    })?);
                }
            }
        }
        EffectTable::from_parts(
            rows.ok_or_else(|| de::Error::missing_field("rows"))?,
            function_starts.ok_or_else(|| de::Error::missing_field("function_starts"))?,
        )
        .map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for EffectTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "EffectTable",
            &["rows", "function_starts"],
            EffectTableVisitor,
        )
    }
}
