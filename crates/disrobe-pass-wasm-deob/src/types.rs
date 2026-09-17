use serde::Serialize;

use crate::gc_types::GcTypeGraph;
use crate::ssa::{LocalId, OpKind, SsaFunction, UnOp, ValueDef, ValueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum LoadKind {
    I32,
    I64,
    F32,
    F64,
    I32_8U,
    I32_8S,
    I32_16U,
    I32_16S,
    I64_8U,
    I64_8S,
    I64_16U,
    I64_16S,
    I64_32U,
    I64_32S,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum StoreKind {
    I32,
    I64,
    F32,
    F64,
    I32_8,
    I32_16,
    I64_8,
    I64_16,
    I64_32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Signedness {
    Unknown,
    Signed,
    Unsigned,
    Conflict,
}

impl Signedness {
    #[inline]
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Unknown, x) | (x, Self::Unknown) => x,
            (Self::Signed, Self::Signed) => Self::Signed,
            (Self::Unsigned, Self::Unsigned) => Self::Unsigned,
            _ => Self::Conflict,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_certain(self) -> bool {
        matches!(self, Self::Signed | Self::Unsigned)
    }
}

impl LoadKind {
    #[inline]
    #[must_use]
    pub const fn width_bytes(self) -> u32 {
        match self {
            Self::I32_8U | Self::I32_8S | Self::I64_8U | Self::I64_8S => 1,
            Self::I32_16U | Self::I32_16S | Self::I64_16U | Self::I64_16S => 2,
            Self::I32 | Self::F32 | Self::I64_32U | Self::I64_32S => 4,
            Self::I64 | Self::F64 => 8,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_integer(self) -> bool {
        !matches!(self, Self::F32 | Self::F64)
    }

    #[inline]
    #[must_use]
    pub const fn signedness(self) -> Signedness {
        match self {
            Self::I32_8S | Self::I32_16S | Self::I64_8S | Self::I64_16S | Self::I64_32S => {
                Signedness::Signed
            }
            Self::I32_8U | Self::I32_16U | Self::I64_8U | Self::I64_16U | Self::I64_32U => {
                Signedness::Unsigned
            }
            Self::I32 | Self::I64 | Self::F32 | Self::F64 => Signedness::Unknown,
        }
    }
}

impl StoreKind {
    #[inline]
    #[must_use]
    pub const fn width_bytes(self) -> u32 {
        match self {
            Self::I32_8 | Self::I64_8 => 1,
            Self::I32_16 | Self::I64_16 => 2,
            Self::I32 | Self::F32 | Self::I64_32 => 4,
            Self::I64 | Self::F64 => 8,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_integer(self) -> bool {
        !matches!(self, Self::F32 | Self::F64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum BaseOrigin {
    Local(LocalId),
    Global(u32),
    Param(u32),
    Heap,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum WasmValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RecoveredStorageType {
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    V128,
}

impl RecoveredStorageType {
    #[inline]
    #[must_use]
    pub const fn width_bytes(self) -> u32 {
        match self {
            Self::I8 => 1,
            Self::I16 => 2,
            Self::I32 | Self::F32 => 4,
            Self::I64 | Self::F64 => 8,
            Self::V128 => 16,
        }
    }

    #[inline]
    #[must_use]
    pub const fn alignment_bytes(self) -> u32 {
        self.width_bytes()
    }
}

impl LoadKind {
    #[inline]
    #[must_use]
    pub const fn storage_type(self) -> RecoveredStorageType {
        match self {
            Self::I32_8U | Self::I32_8S | Self::I64_8U | Self::I64_8S => RecoveredStorageType::I8,
            Self::I32_16U | Self::I32_16S | Self::I64_16U | Self::I64_16S => {
                RecoveredStorageType::I16
            }
            Self::I32 | Self::I64_32U | Self::I64_32S => RecoveredStorageType::I32,
            Self::I64 => RecoveredStorageType::I64,
            Self::F32 => RecoveredStorageType::F32,
            Self::F64 => RecoveredStorageType::F64,
        }
    }
}

impl StoreKind {
    #[inline]
    #[must_use]
    pub const fn storage_type(self) -> RecoveredStorageType {
        match self {
            Self::I32_8 | Self::I64_8 => RecoveredStorageType::I8,
            Self::I32_16 | Self::I64_16 => RecoveredStorageType::I16,
            Self::I32 | Self::I64_32 => RecoveredStorageType::I32,
            Self::I64 => RecoveredStorageType::I64,
            Self::F32 => RecoveredStorageType::F32,
            Self::F64 => RecoveredStorageType::F64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum TypeRecoveryRefusal {
    UnsupportedSsa,
    Memory64,
    AmbiguousAddress,
    AddressDepth,
    OffsetOutOfRange,
    InvalidAccess,
    ConflictingAccess,
    OverlappingAccess,
    InconsistentArray,
    UnrepresentableLayout,
    CyclicAddress,
    AddressBudget,
}

impl TypeRecoveryRefusal {
    #[inline]
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSsa => "DR-WASMDEOB-TYPES-0001",
            Self::Memory64 => "DR-WASMDEOB-TYPES-0002",
            Self::AmbiguousAddress => "DR-WASMDEOB-TYPES-0003",
            Self::AddressDepth => "DR-WASMDEOB-TYPES-0004",
            Self::OffsetOutOfRange => "DR-WASMDEOB-TYPES-0005",
            Self::InvalidAccess => "DR-WASMDEOB-TYPES-0006",
            Self::ConflictingAccess => "DR-WASMDEOB-TYPES-0007",
            Self::OverlappingAccess => "DR-WASMDEOB-TYPES-0008",
            Self::InconsistentArray => "DR-WASMDEOB-TYPES-0009",
            Self::UnrepresentableLayout => "DR-WASMDEOB-TYPES-0010",
            Self::CyclicAddress => "DR-WASMDEOB-TYPES-0011",
            Self::AddressBudget => "DR-WASMDEOB-TYPES-0012",
        }
    }

    #[inline]
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedSsa => "SSA cannot represent every operator in this function",
            Self::Memory64 => "memory64 layouts exceed the declaration address model",
            Self::AmbiguousAddress => "the memory address has no single static base",
            Self::AddressDepth => "the memory address exceeds the bounded analysis depth",
            Self::OffsetOutOfRange => "the memory offset exceeds the declaration range",
            Self::InvalidAccess => "the memory access has no consistent storage type",
            Self::ConflictingAccess => "the same memory offset has conflicting storage types",
            Self::OverlappingAccess => "recovered memory fields overlap",
            Self::InconsistentArray => "indexed memory accesses disagree on element layout",
            Self::UnrepresentableLayout => {
                "the recovered offsets cannot be expressed by the target layout"
            }
            Self::CyclicAddress => "the memory address contains a cyclic SSA dependency",
            Self::AddressBudget => "the memory address exceeds the bounded SSA visit budget",
        }
    }
}

impl core::fmt::Display for TypeRecoveryRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for TypeRecoveryRefusal {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AccessPattern {
    pub load_kind: Option<LoadKind>,
    pub store_kind: Option<StoreKind>,
    pub width: u32,
    pub alignment: u32,
    pub offset_class: i32,
    pub base_origin: BaseOrigin,
    pub is_indexed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FieldRecord {
    pub offset: i32,
    pub width: u32,
    pub kind: RecoveredStorageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum RecoveredType {
    Scalar(WasmValType),
    StorageScalar(RecoveredStorageType),
    Struct {
        fields: Vec<FieldRecord>,
    },
    Array {
        elem_size: u32,
        count: Option<u32>,
    },
    TypedArray {
        elem: RecoveredStorageType,
        count: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredTypes {
    pub memory_aggregates: Vec<(BaseOrigin, RecoveredType)>,
    pub gc_graph: GcTypeGraph,
}

impl RecoveredTypes {
    #[inline]
    #[must_use]
    pub const fn new(
        memory_aggregates: Vec<(BaseOrigin, RecoveredType)>,
        gc_graph: GcTypeGraph,
    ) -> Self {
        Self {
            memory_aggregates,
            gc_graph,
        }
    }

    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memory_aggregates.is_empty() && self.gc_graph.is_empty()
    }
}

#[must_use]
pub fn classify_aggregates(patterns: &[AccessPattern]) -> Vec<(BaseOrigin, RecoveredType)> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<BaseOrigin, Vec<&AccessPattern>> = BTreeMap::new();
    for p in patterns {
        groups.entry(p.base_origin).or_default().push(p);
    }

    let mut out: Vec<(BaseOrigin, RecoveredType)> = Vec::with_capacity(groups.len());
    for (base, members) in groups {
        if members.is_empty() {
            continue;
        }
        if members.iter().any(|p| p.is_indexed) {
            let elem_size: u32 = members.first().map_or(4, |p| p.width);
            out.push((
                base,
                RecoveredType::Array {
                    elem_size,
                    count: None,
                },
            ));
            continue;
        }
        if members.len() == 1 {
            let p: &AccessPattern = members[0];
            out.push((base, RecoveredType::Scalar(width_to_valtype(p.width))));
            continue;
        }
        let mut offsets: Vec<i32> = members.iter().map(|p| p.offset_class).collect();
        offsets.sort_unstable();
        offsets.dedup();
        let strided: bool = is_strided(&offsets, members.first().map_or(4, |p| p.width));
        if strided {
            let elem_size: u32 = members.first().map_or(4, |p| p.width);
            let count: u32 = u32::try_from(offsets.len()).unwrap_or(u32::MAX);
            out.push((
                base,
                RecoveredType::Array {
                    elem_size,
                    count: Some(count),
                },
            ));
            continue;
        }
        let mut fields: Vec<FieldRecord> = members
            .iter()
            .map(|p| {
                let Some(kind): Option<RecoveredStorageType> = access_storage_type(p) else {
                    return FieldRecord {
                        offset: p.offset_class,
                        width: p.width,
                        kind: width_to_storage_type(p.width),
                    };
                };
                FieldRecord {
                    offset: p.offset_class,
                    width: p.width,
                    kind,
                }
            })
            .collect();
        fields.sort_by_key(|f| f.offset);
        fields.dedup_by_key(|f| f.offset);
        out.push((base, RecoveredType::Struct { fields }));
    }
    out
}

pub(crate) fn classify_aggregates_checked(
    patterns: &[AccessPattern],
) -> Result<Vec<(BaseOrigin, RecoveredType)>, TypeRecoveryRefusal> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<BaseOrigin, Vec<&AccessPattern>> = BTreeMap::new();
    for pattern in patterns {
        if pattern.base_origin == BaseOrigin::Unknown || pattern.offset_class < 0 {
            return Err(TypeRecoveryRefusal::AmbiguousAddress);
        }
        let Some(storage_type): Option<RecoveredStorageType> = access_storage_type(pattern) else {
            return Err(TypeRecoveryRefusal::InvalidAccess);
        };
        if storage_type.width_bytes() != pattern.width {
            return Err(TypeRecoveryRefusal::InvalidAccess);
        }
        groups.entry(pattern.base_origin).or_default().push(pattern);
    }

    let mut out: Vec<(BaseOrigin, RecoveredType)> = Vec::with_capacity(groups.len());
    for (base, members) in groups {
        let indexed_count: usize = members
            .iter()
            .filter(|pattern: &&&AccessPattern| pattern.is_indexed)
            .count();
        if indexed_count > 0 {
            if indexed_count != members.len() {
                return Err(TypeRecoveryRefusal::InconsistentArray);
            }
            let first: &AccessPattern = members[0];
            let Some(elem): Option<RecoveredStorageType> = access_storage_type(first) else {
                return Err(TypeRecoveryRefusal::InvalidAccess);
            };
            if first.offset_class != 0
                || members.iter().any(|pattern: &&AccessPattern| {
                    pattern.offset_class != 0 || access_storage_type(pattern) != Some(elem)
                })
            {
                return Err(TypeRecoveryRefusal::InconsistentArray);
            }
            out.push((base, RecoveredType::TypedArray { elem, count: None }));
            continue;
        }

        let mut fields: Vec<FieldRecord> = members
            .iter()
            .map(|pattern: &&AccessPattern| {
                let kind: RecoveredStorageType =
                    access_storage_type(pattern).ok_or(TypeRecoveryRefusal::InvalidAccess)?;
                Ok(FieldRecord {
                    offset: pattern.offset_class,
                    width: pattern.width,
                    kind,
                })
            })
            .collect::<Result<Vec<FieldRecord>, TypeRecoveryRefusal>>()?;
        fields.sort_by_key(|field: &FieldRecord| field.offset);
        let mut unique: Vec<FieldRecord> = Vec::with_capacity(fields.len());
        for field in fields {
            if let Some(previous) = unique.last() {
                if field.offset == previous.offset {
                    if field.width != previous.width || field.kind != previous.kind {
                        return Err(TypeRecoveryRefusal::ConflictingAccess);
                    }
                    continue;
                }
                let previous_end: i32 = previous
                    .offset
                    .checked_add(
                        i32::try_from(previous.width)
                            .map_err(|_| TypeRecoveryRefusal::OffsetOutOfRange)?,
                    )
                    .ok_or(TypeRecoveryRefusal::OffsetOutOfRange)?;
                if field.offset < previous_end {
                    return Err(TypeRecoveryRefusal::OverlappingAccess);
                }
            }
            unique.push(field);
        }
        let Some(first): Option<&FieldRecord> = unique.first() else {
            continue;
        };
        if unique.len() == 1 && first.offset == 0 {
            let recovered: RecoveredType = match first.kind {
                RecoveredStorageType::I8 | RecoveredStorageType::I16 => {
                    RecoveredType::StorageScalar(first.kind)
                }
                RecoveredStorageType::I32 => RecoveredType::Scalar(WasmValType::I32),
                RecoveredStorageType::I64 => RecoveredType::Scalar(WasmValType::I64),
                RecoveredStorageType::F32 => RecoveredType::Scalar(WasmValType::F32),
                RecoveredStorageType::F64 => RecoveredType::Scalar(WasmValType::F64),
                RecoveredStorageType::V128 => RecoveredType::Scalar(WasmValType::V128),
            };
            out.push((base, recovered));
            continue;
        }
        let is_array: bool = first.offset == 0
            && unique
                .iter()
                .enumerate()
                .all(|(index, field): (usize, &FieldRecord)| {
                    field.kind == first.kind
                        && usize::try_from(field.offset).ok()
                            == usize::try_from(first.width)
                                .ok()
                                .and_then(|width: usize| index.checked_mul(width))
                });
        if is_array {
            let count: u32 =
                u32::try_from(unique.len()).map_err(|_| TypeRecoveryRefusal::OffsetOutOfRange)?;
            let recovered: RecoveredType = if first.kind == RecoveredStorageType::I32 {
                RecoveredType::Array {
                    elem_size: first.width,
                    count: Some(count),
                }
            } else {
                RecoveredType::TypedArray {
                    elem: first.kind,
                    count: Some(count),
                }
            };
            out.push((base, recovered));
        } else {
            out.push((base, RecoveredType::Struct { fields: unique }));
        }
    }
    Ok(out)
}

fn is_strided(offsets: &[i32], stride: u32) -> bool {
    if offsets.len() < 2 {
        return false;
    }
    let stride_i: i32 = i32::try_from(stride).unwrap_or(i32::MAX);
    if stride_i == 0 {
        return false;
    }
    let Some(&first): Option<&i32> = offsets.first() else {
        return false;
    };
    offsets.iter().enumerate().all(|(i, off)| {
        let step: i32 = i32::try_from(i)
            .unwrap_or(i32::MAX)
            .saturating_mul(stride_i);
        *off == first.saturating_add(step)
    })
}

const fn width_to_valtype(width: u32) -> WasmValType {
    match width {
        8 => WasmValType::I64,
        16 => WasmValType::V128,
        _ => WasmValType::I32,
    }
}

const fn width_to_storage_type(width: u32) -> RecoveredStorageType {
    match width {
        1 => RecoveredStorageType::I8,
        2 => RecoveredStorageType::I16,
        8 => RecoveredStorageType::I64,
        16 => RecoveredStorageType::V128,
        _ => RecoveredStorageType::I32,
    }
}

fn access_storage_type(pattern: &AccessPattern) -> Option<RecoveredStorageType> {
    match (pattern.load_kind, pattern.store_kind) {
        (Some(load), None) => Some(load.storage_type()),
        (None, Some(store)) => Some(store.storage_type()),
        (Some(load), Some(store)) if load.storage_type() == store.storage_type() => {
            Some(load.storage_type())
        }
        (None, None) | (Some(_), Some(_)) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamedField {
    pub name: String,
    pub offset: i32,
    pub width: u32,
    pub kind: RecoveredStorageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NamedType {
    Struct {
        name: String,
        fields: Vec<NamedField>,
    },
    Array {
        name: String,
        elem: RecoveredStorageType,
        elem_size: u32,
        count: Option<u32>,
    },
    Scalar {
        name: String,
        kind: RecoveredStorageType,
    },
}

impl NamedType {
    #[inline]
    #[must_use]
    pub fn type_name(&self) -> &str {
        match self {
            Self::Struct { name, .. } | Self::Array { name, .. } | Self::Scalar { name, .. } => {
                name
            }
        }
    }
}

#[must_use]
pub fn synthesize_named_types(aggregates: &[(BaseOrigin, RecoveredType)]) -> Vec<NamedType> {
    aggregates
        .iter()
        .map(|(base, ty)| synthesize_one(*base, ty))
        .collect()
}

fn synthesize_one(base: BaseOrigin, ty: &RecoveredType) -> NamedType {
    let suffix: String = base_suffix(base);
    match ty {
        RecoveredType::Scalar(kind) => NamedType::Scalar {
            name: format!("Scalar_{suffix}"),
            kind: wasm_val_to_storage_type(*kind),
        },
        RecoveredType::StorageScalar(kind) => NamedType::Scalar {
            name: format!("Scalar_{suffix}"),
            kind: *kind,
        },
        RecoveredType::Array { elem_size, count } => NamedType::Array {
            name: format!("Array_{suffix}"),
            elem: width_to_storage_type(*elem_size),
            elem_size: *elem_size,
            count: *count,
        },
        RecoveredType::TypedArray { elem, count } => NamedType::Array {
            name: format!("Array_{suffix}"),
            elem: *elem,
            elem_size: elem.width_bytes(),
            count: *count,
        },
        RecoveredType::Struct { fields } => NamedType::Struct {
            name: format!("Struct_{suffix}"),
            fields: fields
                .iter()
                .map(|f| NamedField {
                    name: field_name(f.offset),
                    offset: f.offset,
                    width: f.width,
                    kind: f.kind,
                })
                .collect(),
        },
    }
}

const fn wasm_val_to_storage_type(kind: WasmValType) -> RecoveredStorageType {
    match kind {
        WasmValType::I32 => RecoveredStorageType::I32,
        WasmValType::I64 => RecoveredStorageType::I64,
        WasmValType::F32 => RecoveredStorageType::F32,
        WasmValType::F64 => RecoveredStorageType::F64,
        WasmValType::V128 => RecoveredStorageType::V128,
        WasmValType::FuncRef | WasmValType::ExternRef => RecoveredStorageType::I32,
    }
}

fn base_suffix(base: BaseOrigin) -> String {
    match base {
        BaseOrigin::Local(id) => format!("local{}", id.0),
        BaseOrigin::Global(g) => format!("global{g}"),
        BaseOrigin::Param(p) => format!("param{p}"),
        BaseOrigin::Heap => "heap".to_owned(),
        BaseOrigin::Unknown => "anon".to_owned(),
    }
}

fn field_name(offset: i32) -> String {
    if offset < 0 {
        format!("field_neg{}", offset.unsigned_abs())
    } else {
        format!("field_{offset}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct ScalarIntType {
    pub width_bytes: u32,
    pub signedness: Signedness,
}

impl ScalarIntType {
    #[inline]
    #[must_use]
    pub const fn new(width_bytes: u32, signedness: Signedness) -> Self {
        Self {
            width_bytes,
            signedness,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_signedness_certain(self) -> bool {
        self.signedness.is_certain()
    }

    #[must_use]
    pub const fn c_name(self) -> &'static str {
        let signed: bool = matches!(self.signedness, Signedness::Signed);
        match (self.width_bytes, signed) {
            (1, true) => "int8_t",
            (1, false) => "uint8_t",
            (2, true) => "int16_t",
            (2, false) => "uint16_t",
            (4, true) => "int32_t",
            (4, false) => "uint32_t",
            (8, true) => "int64_t",
            (8, false) => "uint64_t",
            _ => "uint32_t",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct PointerType {
    pub elem: ScalarIntType,
}

impl PointerType {
    #[inline]
    #[must_use]
    pub const fn new(elem: ScalarIntType) -> Self {
        Self { elem }
    }

    #[must_use]
    pub fn c_name(self) -> String {
        format!("{}*", self.elem.c_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignednessReport {
    pub value_signedness: Vec<Signedness>,
    pub pointer_types: Vec<(BaseOrigin, PointerType)>,
}

impl SignednessReport {
    #[inline]
    #[must_use]
    pub fn value(&self, v: ValueId) -> Signedness {
        self.value_signedness
            .get(v.0 as usize)
            .copied()
            .unwrap_or(Signedness::Unknown)
    }

    #[inline]
    #[must_use]
    pub fn pointer(&self, base: BaseOrigin) -> Option<PointerType> {
        self.pointer_types
            .iter()
            .find(|(candidate, _)| *candidate == base)
            .map(|(_, ty)| *ty)
    }
}

#[derive(Clone, Copy)]
enum ArgSignRule {
    None,
    Both(Signedness),
    FirstOnly(Signedness),
}

const fn op_result_signedness(kind: OpKind) -> Signedness {
    match kind {
        OpKind::I32DivS
        | OpKind::I64DivS
        | OpKind::I32RemS
        | OpKind::I64RemS
        | OpKind::I32ShrS
        | OpKind::I64ShrS => Signedness::Signed,
        OpKind::I32DivU
        | OpKind::I64DivU
        | OpKind::I32RemU
        | OpKind::I64RemU
        | OpKind::I32ShrU
        | OpKind::I64ShrU => Signedness::Unsigned,
        _ => Signedness::Unknown,
    }
}

const fn op_arg_signedness(kind: OpKind) -> ArgSignRule {
    match kind {
        OpKind::I32LtS
        | OpKind::I32GtS
        | OpKind::I32LeS
        | OpKind::I32GeS
        | OpKind::I64LtS
        | OpKind::I64GtS
        | OpKind::I64LeS
        | OpKind::I64GeS
        | OpKind::I32DivS
        | OpKind::I64DivS
        | OpKind::I32RemS
        | OpKind::I64RemS => ArgSignRule::Both(Signedness::Signed),
        OpKind::I32LtU
        | OpKind::I32GtU
        | OpKind::I32LeU
        | OpKind::I32GeU
        | OpKind::I64LtU
        | OpKind::I64GtU
        | OpKind::I64LeU
        | OpKind::I64GeU
        | OpKind::I32DivU
        | OpKind::I64DivU
        | OpKind::I32RemU
        | OpKind::I64RemU => ArgSignRule::Both(Signedness::Unsigned),
        OpKind::I32ShrS | OpKind::I64ShrS => ArgSignRule::FirstOnly(Signedness::Signed),
        OpKind::I32ShrU | OpKind::I64ShrU => ArgSignRule::FirstOnly(Signedness::Unsigned),
        _ => ArgSignRule::None,
    }
}

const fn unary_result_signedness(op: UnOp) -> Signedness {
    match op {
        UnOp::I64ExtendI32S
        | UnOp::I32Extend8S
        | UnOp::I32Extend16S
        | UnOp::I64Extend8S
        | UnOp::I64Extend16S
        | UnOp::I64Extend32S
        | UnOp::I32TruncF32S
        | UnOp::I32TruncF64S
        | UnOp::I64TruncF32S
        | UnOp::I64TruncF64S
        | UnOp::I32TruncSatF32S
        | UnOp::I32TruncSatF64S
        | UnOp::I64TruncSatF32S
        | UnOp::I64TruncSatF64S => Signedness::Signed,
        UnOp::I64ExtendI32U
        | UnOp::I32TruncF32U
        | UnOp::I32TruncF64U
        | UnOp::I64TruncF32U
        | UnOp::I64TruncF64U
        | UnOp::I32TruncSatF32U
        | UnOp::I32TruncSatF64U
        | UnOp::I64TruncSatF32U
        | UnOp::I64TruncSatF64U => Signedness::Unsigned,
        _ => Signedness::Unknown,
    }
}

const fn unary_arg_signedness(op: UnOp) -> Option<Signedness> {
    match op {
        UnOp::I64ExtendI32S
        | UnOp::I32Extend8S
        | UnOp::I32Extend16S
        | UnOp::I64Extend8S
        | UnOp::I64Extend16S
        | UnOp::I64Extend32S
        | UnOp::F32ConvertI32S
        | UnOp::F32ConvertI64S
        | UnOp::F64ConvertI32S
        | UnOp::F64ConvertI64S => Some(Signedness::Signed),
        UnOp::I64ExtendI32U
        | UnOp::F32ConvertI32U
        | UnOp::F32ConvertI64U
        | UnOp::F64ConvertI32U
        | UnOp::F64ConvertI64U => Some(Signedness::Unsigned),
        _ => None,
    }
}

fn sign_at(slots: &[Signedness], v: ValueId) -> Signedness {
    slots
        .get(v.0 as usize)
        .copied()
        .unwrap_or(Signedness::Unknown)
}

fn vote(slots: &mut [Signedness], v: ValueId, s: Signedness) {
    if let Some(slot) = slots.get_mut(v.0 as usize) {
        *slot = slot.join(s);
    }
}

struct MemAccess {
    width: u32,
    sign: Signedness,
}

#[must_use]
pub fn recover_signedness(ssa: &SsaFunction) -> SignednessReport {
    let count: usize = ssa.values.len();
    let mut prod: Vec<Signedness> = vec![Signedness::Unknown; count];
    let mut cons: Vec<Signedness> = vec![Signedness::Unknown; count];

    for (index, def) in ssa.values.iter().enumerate() {
        match def {
            ValueDef::Load { kind, .. } => {
                prod[index] = kind.signedness();
            }
            ValueDef::Unary { op, arg, .. } => {
                prod[index] = unary_result_signedness(*op);
                if let Some(s) = unary_arg_signedness(*op) {
                    vote(&mut cons, *arg, s);
                }
            }
            ValueDef::Op { kind, args, .. } => {
                prod[index] = op_result_signedness(*kind);
                match op_arg_signedness(*kind) {
                    ArgSignRule::None => {}
                    ArgSignRule::Both(s) => {
                        for arg in args.iter().take(2) {
                            vote(&mut cons, *arg, s);
                        }
                    }
                    ArgSignRule::FirstOnly(s) => {
                        if let Some(arg) = args.first() {
                            vote(&mut cons, *arg, s);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let cap: usize = count.saturating_add(2);
    let mut iterations: usize = 0;
    loop {
        let mut changed: bool = false;
        for (index, def) in ssa.values.iter().enumerate() {
            let incoming: Signedness = match def {
                ValueDef::Phi { operands, .. } => operands
                    .iter()
                    .fold(Signedness::Unknown, |acc: Signedness, op: &ValueId| {
                        acc.join(sign_at(&prod, *op))
                    }),
                ValueDef::Select {
                    if_true, if_false, ..
                } => sign_at(&prod, *if_true).join(sign_at(&prod, *if_false)),
                _ => continue,
            };
            let merged: Signedness = prod[index].join(incoming);
            if merged != prod[index] {
                prod[index] = merged;
                changed = true;
            }
        }
        iterations += 1;
        if !changed || iterations >= cap {
            break;
        }
    }

    let value_signedness: Vec<Signedness> = (0..count)
        .map(|index: usize| {
            if matches!(prod[index], Signedness::Unknown) {
                cons[index]
            } else {
                prod[index]
            }
        })
        .collect();

    let pointer_types: Vec<(BaseOrigin, PointerType)> =
        recover_pointer_types(ssa, &value_signedness);

    SignednessReport {
        value_signedness,
        pointer_types,
    }
}

fn recover_pointer_types(
    ssa: &SsaFunction,
    value_signedness: &[Signedness],
) -> Vec<(BaseOrigin, PointerType)> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<BaseOrigin, Vec<MemAccess>> = BTreeMap::new();

    for block in &ssa.blocks {
        for vid in &block.instrs {
            let Some(ValueDef::Load { addr, kind, .. }): Option<&ValueDef> =
                ssa.values.get(vid.0 as usize)
            else {
                continue;
            };
            if !kind.is_integer() {
                continue;
            }
            let base: BaseOrigin = crate::classify_base_origin(*addr, ssa);
            let sign: Signedness = match kind.signedness() {
                Signedness::Unknown => sign_at(value_signedness, *vid),
                resolved => resolved,
            };
            groups.entry(base).or_default().push(MemAccess {
                width: kind.width_bytes(),
                sign,
            });
        }
        for store in &block.stores {
            if !store.kind.is_integer() {
                continue;
            }
            let base: BaseOrigin = crate::classify_base_origin(store.addr, ssa);
            groups.entry(base).or_default().push(MemAccess {
                width: store.kind.width_bytes(),
                sign: sign_at(value_signedness, store.val),
            });
        }
    }

    let mut out: Vec<(BaseOrigin, PointerType)> = Vec::with_capacity(groups.len());
    for (base, accesses) in groups {
        if matches!(base, BaseOrigin::Unknown) {
            continue;
        }
        let Some(first): Option<&MemAccess> = accesses.first() else {
            continue;
        };
        let width: u32 = first.width;
        if accesses
            .iter()
            .any(|access: &MemAccess| access.width != width)
        {
            continue;
        }
        let sign: Signedness = accesses.iter().fold(
            Signedness::Unknown,
            |acc: Signedness, access: &MemAccess| acc.join(access.sign),
        );
        out.push((base, PointerType::new(ScalarIntType::new(width, sign))));
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pat(base: BaseOrigin, offset: i32, width: u32) -> AccessPattern {
        AccessPattern {
            load_kind: Some(LoadKind::I32),
            store_kind: None,
            width,
            alignment: width,
            offset_class: offset,
            base_origin: base,
            is_indexed: false,
        }
    }

    #[test]
    fn single_access_yields_scalar() {
        let p: AccessPattern = pat(BaseOrigin::Local(LocalId(0)), 0, 4);
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&[p]);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].1, RecoveredType::Scalar(WasmValType::I32)));
    }

    #[test]
    fn strided_accesses_yield_array() {
        let base: BaseOrigin = BaseOrigin::Local(LocalId(0));
        let patterns: Vec<AccessPattern> = vec![pat(base, 0, 4), pat(base, 4, 4), pat(base, 8, 4)];
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&patterns);
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].1,
            RecoveredType::Array {
                elem_size: 4,
                count: Some(3)
            }
        ));
    }

    #[test]
    fn distinct_offsets_yield_struct() {
        let base: BaseOrigin = BaseOrigin::Local(LocalId(0));
        let patterns: Vec<AccessPattern> = vec![pat(base, 0, 4), pat(base, 4, 4), pat(base, 12, 4)];
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&patterns);
        assert_eq!(out.len(), 1);
        match &out[0].1 {
            RecoveredType::Struct { fields } => {
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].offset, 0);
                assert_eq!(fields[1].offset, 4);
                assert_eq!(fields[2].offset, 12);
            }
            other => panic!("expected struct, got {other:?}"),
        }
    }

    #[test]
    fn indexed_access_yields_array_unknown_count() {
        let mut p: AccessPattern = pat(BaseOrigin::Local(LocalId(0)), 0, 4);
        p.is_indexed = true;
        let out: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&[p]);
        assert!(matches!(out[0].1, RecoveredType::Array { count: None, .. }));
    }

    #[test]
    fn named_struct_synthesizes_offset_field_names() {
        let base: BaseOrigin = BaseOrigin::Param(2);
        let mut wide: AccessPattern = pat(base, 12, 8);
        wide.load_kind = Some(LoadKind::I64);
        let patterns: Vec<AccessPattern> = vec![pat(base, 0, 4), pat(base, 4, 4), wide];
        let aggregates: Vec<(BaseOrigin, RecoveredType)> = classify_aggregates(&patterns);
        let named: Vec<NamedType> = synthesize_named_types(&aggregates);
        assert_eq!(named.len(), 1);
        match &named[0] {
            NamedType::Struct { name, fields } => {
                assert_eq!(name, "Struct_param2");
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].name, "field_0");
                assert_eq!(fields[1].name, "field_4");
                assert_eq!(fields[2].name, "field_12");
                assert_eq!(fields[2].kind, RecoveredStorageType::I64);
            }
            other => panic!("expected named struct, got {other:?}"),
        }
    }

    #[test]
    fn named_array_and_scalar_naming() {
        let arr_base: BaseOrigin = BaseOrigin::Global(5);
        let arr: Vec<AccessPattern> = vec![
            pat(arr_base, 0, 4),
            pat(arr_base, 4, 4),
            pat(arr_base, 8, 4),
        ];
        let named: Vec<NamedType> = synthesize_named_types(&classify_aggregates(&arr));
        assert_eq!(named[0].type_name(), "Array_global5");

        let scalar_base: BaseOrigin = BaseOrigin::Local(LocalId(1));
        let scalar: Vec<AccessPattern> = vec![pat(scalar_base, 0, 4)];
        let named_scalar: Vec<NamedType> = synthesize_named_types(&classify_aggregates(&scalar));
        assert!(matches!(named_scalar[0], NamedType::Scalar { .. }));
        assert_eq!(named_scalar[0].type_name(), "Scalar_local1");
    }
}
