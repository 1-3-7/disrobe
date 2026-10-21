use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    AotCodeRange, AotMetadataAttribution, AotStackTraceMap, AotTypeLayout, AotTypeSignature,
};
use crate::pe::PeBitness;
use disrobe_pass_native::{Arch, DisasmInsn, disassemble};

const AMD64_MACHINE: u16 = 0x8664;
const MAX_METHOD_EVIDENCE: usize = 65_536;
const MAX_METHOD_BYTES: usize = 256 * 1024;
const MAX_TOTAL_METHOD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIELD_STORES: usize = 16_384;
const MAX_HELPERS: usize = 4_096;
const MAX_HELPER_CALLS: usize = 16_384;
const MAX_METHOD_TABLES: usize = 65_536;
const MAX_TYPE_REFERENCES: usize = 16_384;
const MAX_RUNTIME_FIELD_LAYOUTS: usize = 1_048_576;
const MAX_FIELD_INITIALIZERS: usize = 16_384;
const MAX_FIELD_OFFSET: u32 = 0x00FF_FFFF;
const MAX_REFERENCE_STORES: usize = 16_384;
const MAX_FROZEN_STRING_CHARS: u32 = 65_536;
const METHOD_TABLE_HAS_COMPONENT_SIZE: u32 = 0x8000_0000;
const METHOD_TABLE_ELEMENT_TYPE_MASK: u32 = 0x7C00_0000;
const METHOD_TABLE_ELEMENT_TYPE_SHIFT: u32 = 26;
const METHOD_TABLE_KIND_MASK: u32 = 0x0003_0000;
const METHOD_TABLE_ELEMENT_TYPE_CLASS: u32 = 0x14;
const STRING_COMPONENT_SIZE: u32 = 2;
const FROZEN_STRING_LENGTH_OFFSET: u32 = 8;
const FROZEN_STRING_CHARS_OFFSET: u32 = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AotObjectModelStatus {
    NotPresent,
    Recovered,
    Refused { reason: AotObjectModelRefusal },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AotObjectModelRefusal {
    UnsupportedContainer,
    MethodEvidenceCountExceeded,
    MethodEvidenceAmbiguous,
    MethodEvidenceDoesNotMatchMetadata,
    DuplicateTypeLayout,
    MethodRangeInvalid,
    MethodRangeExceeded,
    DisassemblyFailed,
    AggregateMethodBytesExceeded,
    FieldStoreLimitExceeded,
    HelperCallLimitExceeded,
    HelperEvidenceAmbiguous,
    MethodTableEvidenceAmbiguous,
    MethodTableLimitExceeded,
    TypeReferenceLimitExceeded,
    RuntimeFieldLayoutLimitExceeded,
    RuntimeFieldLayoutAmbiguous,
    RuntimeFieldLayoutDoesNotMatchMetadata,
    FieldInitializerLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectModel {
    pub status: AotObjectModelStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_layouts: Vec<AotTypeLayout>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_stores: Vec<AotObjectFieldStore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helper_calls: Vec<AotObjectHelperCall>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_references: Vec<AotObjectTypeReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_initializers: Vec<AotObjectFieldInitializer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reference_stores: Vec<AotObjectReferenceStore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frozen_strings: Vec<AotObjectFrozenString>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectReferenceStore {
    pub type_record_offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub store_rva: u32,
    pub field_offset: u32,
    pub object_rva: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<AotTypeSignature>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectFrozenString {
    pub type_record_offset: u32,
    pub store_rva: u32,
    pub field_offset: u32,
    pub object_rva: u32,
    pub method_table_rva: u32,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
}
impl Default for AotObjectModel {
    fn default() -> Self {
        Self {
            status: AotObjectModelStatus::NotPresent,
            type_layouts: Vec::new(),
            field_stores: Vec::new(),
            helper_calls: Vec::new(),
            type_references: Vec::new(),
            field_initializers: Vec::new(),
            reference_stores: Vec::new(),
            frozen_strings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectMethodEvidence {
    pub type_record_offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub start_rva: u32,
    pub end_rva: u32,
    pub constructor: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AotObjectStoreWidth {
    Pointer,
    Dword,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectFieldStore {
    pub type_record_offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub store_rva: u32,
    pub field_offset: u32,
    pub width: AotObjectStoreWidth,
    pub source_register: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<AotTypeSignature>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AotObjectHelperKind {
    Allocation,
    WriteBarrier,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectHelperEvidence {
    pub rva: u32,
    pub name: String,
    pub kind: AotObjectHelperKind,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectHelperCall {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub call_rva: u32,
    pub helper: AotObjectHelperEvidence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectTypeReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub instruction_rva: u32,
    pub type_record_offset: u32,
    pub method_table_rva: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AotObjectConstant {
    Byte(u8),
    Word(u16),
    Dword(u32),
    Qword(u64),
}
impl AotObjectConstant {
    const fn width(self) -> u32 {
        match self {
            Self::Byte(_) => 1,
            Self::Word(_) => 2,
            Self::Dword(_) => 4,
            Self::Qword(_) => 8,
        }
    }
    const fn to_le_bytes(self) -> [u8; 8] {
        match self {
            Self::Byte(value) => (value as u64).to_le_bytes(),
            Self::Word(value) => (value as u64).to_le_bytes(),
            Self::Dword(value) => (value as u64).to_le_bytes(),
            Self::Qword(value) => value.to_le_bytes(),
        }
    }
    fn slice(self, start: u32, width: u32) -> Option<Self> {
        let bytes: [u8; 8] = self.to_le_bytes();
        let start: usize = usize::try_from(start).ok()?;
        let end: usize = start.checked_add(usize::try_from(width).ok()?)?;
        if end > usize::try_from(self.width()).ok()? {
            return None;
        }
        Self::from_le_slice(bytes.get(start..end)?)
    }
    fn from_le_slice(part: &[u8]) -> Option<Self> {
        match part.len() {
            1 => Some(Self::Byte(*part.first()?)),
            2 => Some(Self::Word(u16::from_le_bytes(part.try_into().ok()?))),
            4 => Some(Self::Dword(u32::from_le_bytes(part.try_into().ok()?))),
            8 => Some(Self::Qword(u64::from_le_bytes(part.try_into().ok()?))),
            _ => None,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectFieldInitializer {
    pub type_record_offset: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_record_offset: Option<u32>,
    pub store_rva: u32,
    pub field_offset: u32,
    pub value: AotObjectConstant,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<AotTypeSignature>,
}

const fn refused(
    reason: AotObjectModelRefusal,
    type_layouts: Vec<AotTypeLayout>,
) -> AotObjectModel {
    AotObjectModel {
        status: AotObjectModelStatus::Refused { reason },
        type_layouts,
        field_stores: Vec::new(),
        helper_calls: Vec::new(),
        type_references: Vec::new(),
        field_initializers: Vec::new(),
        reference_stores: Vec::new(),
        frozen_strings: Vec::new(),
    }
}
struct ThisOperand {
    register: u8,
    offset: u32,
    end: usize,
}
fn this_operand(bytes: &[u8], at: usize) -> Option<ThisOperand> {
    let modrm: u8 = *bytes.get(at)?;
    let register: u8 = (modrm >> 3) & 7;
    match modrm & 0b1100_0111 {
        0b0100_0001 => {
            let offset: u32 = u32::from(*bytes.get(at.checked_add(1)?)?);
            (offset != 0).then_some(ThisOperand {
                register,
                offset,
                end: at.checked_add(2)?,
            })
        }
        0b1000_0001 => {
            let end: usize = at.checked_add(5)?;
            let displacement: [u8; 4] = bytes.get(at.checked_add(1)?..end)?.try_into().ok()?;
            let offset: u32 = u32::from_le_bytes(displacement);
            (offset != 0 && offset <= MAX_FIELD_OFFSET).then_some(ThisOperand {
                register,
                offset,
                end,
            })
        }
        _ => None,
    }
}
fn field_store(bytes: &[u8], at: usize) -> Option<(AotObjectStoreWidth, u8, u32)> {
    let first = *bytes.get(at)?;
    let (width, modrm_at) = match first {
        0x48 if bytes.get(at.checked_add(1)?) == Some(&0x89) => {
            (AotObjectStoreWidth::Pointer, at.checked_add(2)?)
        }
        0x89 => (AotObjectStoreWidth::Dword, at.checked_add(1)?),
        _ => return None,
    };
    let operand: ThisOperand = this_operand(bytes, modrm_at)?;
    (operand.end == bytes.len()).then_some((width, operand.register, operand.offset))
}
fn call_target(rva: u32, bytes: &[u8], at: usize) -> Option<u32> {
    let displacement: [u8; 4] = bytes
        .get(at.checked_add(1)?..at.checked_add(5)?)?
        .try_into()
        .ok()?;
    let target =
        i64::from(rva.checked_add(5)?).checked_add(i64::from(i32::from_le_bytes(displacement)))?;
    u32::try_from(target).ok()
}
fn method_table_target(rva: u32, bytes: &[u8]) -> Option<u32> {
    if bytes.get(..3)? != [0x48, 0x8d, 0x0d] {
        return None;
    }
    let displacement: [u8; 4] = bytes.get(3..7)?.try_into().ok()?;
    let target =
        i64::from(rva.checked_add(7)?).checked_add(i64::from(i32::from_le_bytes(displacement)))?;
    u32::try_from(target).ok()
}
fn immediate_initializer(
    bytes: &[u8],
    modrm_at: usize,
    width: u32,
) -> Option<(u32, AotObjectConstant)> {
    let operand: ThisOperand = this_operand(bytes, modrm_at)?;
    let immediate: &[u8] = bytes.get(operand.end..)?;
    let value: AotObjectConstant = if width == 8 {
        let displacement: [u8; 4] = immediate.try_into().ok()?;
        AotObjectConstant::Qword(i64::from(i32::from_le_bytes(displacement)) as u64)
    } else {
        let value: AotObjectConstant = AotObjectConstant::from_le_slice(immediate)?;
        if value.width() != width {
            return None;
        }
        value
    };
    Some((operand.offset, value))
}
fn register_initializer(
    bytes: &[u8],
    modrm_at: usize,
    prior: Option<&[u8]>,
) -> Option<(u32, AotObjectConstant)> {
    let operand: ThisOperand = this_operand(bytes, modrm_at)?;
    if operand.end != bytes.len() || operand.register != 0 {
        return None;
    }
    let (width, immediate): (u32, &[u8]) = match (modrm_at, prior?) {
        (1, [0xb8, immediate @ ..]) => (4, immediate),
        (2, [0x48, 0xb8, immediate @ ..]) => (8, immediate),
        _ => return None,
    };
    let value: AotObjectConstant = AotObjectConstant::from_le_slice(immediate)?;
    (value.width() == width).then_some((operand.offset, value))
}
fn field_initializer(bytes: &[u8], prior: Option<&[u8]>) -> Option<(u32, AotObjectConstant)> {
    match bytes {
        [0xc6, ..] => immediate_initializer(bytes, 1, 1),
        [0x66, 0xc7, ..] => immediate_initializer(bytes, 2, 2),
        [0xc7, ..] => immediate_initializer(bytes, 1, 4),
        [0x48, 0xc7, ..] => immediate_initializer(bytes, 2, 8),
        [0x89, ..] => register_initializer(bytes, 1, prior),
        [0x48, 0x89, ..] => register_initializer(bytes, 2, prior),
        _ => None,
    }
}
fn split_initializer(
    field_offsets: Option<&BTreeSet<u32>>,
    store_offset: u32,
    value: AotObjectConstant,
) -> Vec<(u32, AotObjectConstant)> {
    let store_end: u32 = store_offset.saturating_add(value.width());
    let covered: Vec<u32> = field_offsets.map_or_else(Vec::new, |offsets| {
        offsets.range(store_offset..store_end).copied().collect()
    });
    if covered.first() != Some(&store_offset) {
        return vec![(store_offset, value)];
    }
    let mut parts: Vec<(u32, AotObjectConstant)> = Vec::with_capacity(covered.len());
    for (index, field_offset) in covered.iter().enumerate() {
        let next: u32 = covered
            .get(index.saturating_add(1))
            .copied()
            .unwrap_or(store_end);
        let Some(part) = value.slice(field_offset - store_offset, next - field_offset) else {
            return vec![(store_offset, value)];
        };
        parts.push((*field_offset, part));
    }
    parts
}
pub fn constructor_evidence(
    image: &[u8],
    attribution: &AotMetadataAttribution,
    stack_trace_map: &AotStackTraceMap,
) -> Vec<AotObjectMethodEvidence> {
    if !image.starts_with(b"MZ") {
        return Vec::new();
    }
    let Ok(pe) = crate::pe::parse(image) else {
        return Vec::new();
    };
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return Vec::new();
    }
    let Ok(Some(ranges)): crate::error::Result<Option<Vec<AotCodeRange>>> =
        super::method_boundaries::read_ranges(image, &pe)
    else {
        return Vec::new();
    };
    let range_at = |entrypoint_rva: u32| -> Option<AotCodeRange> {
        ranges
            .binary_search_by_key(&entrypoint_rva, |range: &AotCodeRange| range.start_rva)
            .ok()
            .and_then(|index: usize| ranges.get(index).copied())
            .filter(|range: &AotCodeRange| range.start_rva < range.end_rva)
    };
    let constructors: BTreeMap<u32, Option<u32>> = attribution
        .methods
        .iter()
        .filter(|method| method.name == ".ctor")
        .map(|method| {
            (
                method.record_offset,
                method
                    .signature
                    .as_ref()
                    .map(|signature| signature.record_offset),
            )
        })
        .collect();
    let mut bound: BTreeMap<(u32, Option<u32>, u32), Option<AotCodeRange>> = BTreeMap::new();
    let mut bind =
        |type_record_offset: u32, method_record_offset: Option<u32>, range: AotCodeRange| {
            let body: u32 = if method_record_offset.is_some() {
                0
            } else {
                range.start_rva
            };
            bound
                .entry((type_record_offset, method_record_offset, body))
                .and_modify(|existing: &mut Option<AotCodeRange>| {
                    if *existing != Some(range) {
                        *existing = None;
                    }
                })
                .or_insert(Some(range));
        };
    for entrypoint in &attribution.owned_entrypoints {
        if constructors.contains_key(&entrypoint.method_record_offset)
            && let Some(range) = range_at(entrypoint.entrypoint_rva)
        {
            bind(
                entrypoint.type_record_offset,
                Some(entrypoint.method_record_offset),
                range,
            );
        }
    }
    for method in &stack_trace_map.methods {
        let (Some(range), Some(name)) = (method.code_range, method.name.as_ref()) else {
            continue;
        };
        if name.method_name != ".ctor"
            || !name.type_arguments.is_empty()
            || !name.method_generic_arguments.is_empty()
        {
            continue;
        }
        let Some(type_record_offset) = name.owning_type_record_offset else {
            continue;
        };
        let Some(type_record) = attribution
            .types
            .iter()
            .find(|type_record| type_record.record_offset == type_record_offset)
        else {
            continue;
        };
        let mut matching =
            type_record
                .method_record_offsets
                .iter()
                .copied()
                .filter(|method_record_offset| {
                    constructors
                        .get(method_record_offset)
                        .is_some_and(|signature| *signature == Some(name.signature_record_offset))
                });
        let method_record_offset: Option<u32> = match (matching.next(), matching.next()) {
            (Some(method_record_offset), None) => Some(method_record_offset),
            (None, None) => None,
            _ => continue,
        };
        bind(type_record_offset, method_record_offset, range);
    }
    let mut claims: BTreeMap<AotCodeRange, usize> = BTreeMap::new();
    for range in bound.values().flatten() {
        *claims.entry(*range).or_insert(0) += 1;
    }
    let mut evidence: Vec<AotObjectMethodEvidence> = bound
        .iter()
        .filter_map(
            |((type_record_offset, method_record_offset, _body), range)| {
                let range: AotCodeRange = (*range)?;
                (claims.get(&range) == Some(&1)).then_some(AotObjectMethodEvidence {
                    type_record_offset: *type_record_offset,
                    method_record_offset: *method_record_offset,
                    start_rva: range.start_rva,
                    end_rva: range.end_rva,
                    constructor: true,
                })
            },
        )
        .collect();
    evidence
        .sort_unstable_by_key(|entry| (entry.start_rva, entry.end_rva, entry.method_record_offset));
    let mut keep: Vec<bool> = vec![true; evidence.len()];
    for index in 1..evidence.len() {
        if evidence[index - 1].end_rva > evidence[index].start_rva {
            keep[index - 1] = false;
            keep[index] = false;
        }
    }
    evidence
        .into_iter()
        .zip(keep)
        .filter_map(|(entry, kept)| kept.then_some(entry))
        .collect()
}
pub fn recover_object_model(
    image: &[u8],
    attribution: &AotMetadataAttribution,
    type_layouts: Vec<AotTypeLayout>,
    method_evidence: &[AotObjectMethodEvidence],
    helper_evidence: &[AotObjectHelperEvidence],
) -> AotObjectModel {
    if method_evidence.is_empty() {
        return AotObjectModel {
            type_layouts,
            ..AotObjectModel::default()
        };
    }
    if method_evidence.len() > MAX_METHOD_EVIDENCE {
        return refused(
            AotObjectModelRefusal::MethodEvidenceCountExceeded,
            type_layouts,
        );
    }
    let mut layout_offsets: BTreeSet<u32> = BTreeSet::new();
    for layout in &type_layouts {
        if !layout_offsets.insert(layout.record_offset) {
            return refused(AotObjectModelRefusal::DuplicateTypeLayout, type_layouts);
        }
    }
    if attribution.runtime_field_layouts.len() > MAX_RUNTIME_FIELD_LAYOUTS {
        return refused(
            AotObjectModelRefusal::RuntimeFieldLayoutLimitExceeded,
            type_layouts,
        );
    }
    let metadata_fields: BTreeMap<(u32, u32), (String, AotTypeSignature)> = type_layouts
        .iter()
        .flat_map(|layout: &AotTypeLayout| {
            layout.instance_fields.iter().map(|field| {
                (
                    (layout.record_offset, field.record_offset),
                    (field.name.clone(), field.field_type),
                )
            })
        })
        .collect();
    let mut fields_by_offset: BTreeMap<(u32, u32), (u32, String, AotTypeSignature)> =
        BTreeMap::new();
    for runtime in &attribution.runtime_field_layouts {
        let Some((name, field_type)): Option<&(String, AotTypeSignature)> =
            metadata_fields.get(&(runtime.type_record_offset, runtime.field_record_offset))
        else {
            return refused(
                AotObjectModelRefusal::RuntimeFieldLayoutDoesNotMatchMetadata,
                type_layouts,
            );
        };
        let key: (u32, u32) = (runtime.type_record_offset, runtime.field_offset);
        if fields_by_offset
            .insert(
                key,
                (runtime.field_record_offset, name.clone(), *field_type),
            )
            .is_some_and(|(record_offset, _name, _field_type)| {
                record_offset != runtime.field_record_offset
            })
        {
            return refused(
                AotObjectModelRefusal::RuntimeFieldLayoutAmbiguous,
                type_layouts,
            );
        }
    }
    let mut offsets_by_type: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (type_record_offset, field_offset) in fields_by_offset.keys() {
        offsets_by_type
            .entry(*type_record_offset)
            .or_default()
            .insert(*field_offset);
    }
    let known: BTreeSet<(u32, u32)> = attribution
        .types
        .iter()
        .flat_map(|type_record| {
            type_record
                .method_record_offsets
                .iter()
                .map(|method| (type_record.record_offset, *method))
        })
        .collect();
    let known_types: BTreeSet<u32> = attribution
        .types
        .iter()
        .map(|type_record| type_record.record_offset)
        .collect();
    let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(method_evidence.len());
    for evidence in method_evidence {
        let matches_metadata: bool = evidence.method_record_offset.map_or_else(
            || known_types.contains(&evidence.type_record_offset),
            |method_record_offset| {
                known.contains(&(evidence.type_record_offset, method_record_offset))
            },
        );
        if evidence.start_rva >= evidence.end_rva || !matches_metadata {
            return refused(
                AotObjectModelRefusal::MethodEvidenceDoesNotMatchMetadata,
                type_layouts,
            );
        }
        ranges.push((evidence.start_rva, evidence.end_rva));
    }
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|pair: &[(u32, u32)]| pair[0].1 > pair[1].0)
    {
        return refused(AotObjectModelRefusal::MethodEvidenceAmbiguous, type_layouts);
    }
    if helper_evidence.len() > MAX_HELPERS {
        return refused(AotObjectModelRefusal::HelperEvidenceAmbiguous, type_layouts);
    }
    let mut helpers: BTreeMap<u32, AotObjectHelperEvidence> = BTreeMap::new();
    for helper in helper_evidence {
        if helper.name.is_empty()
            || helper.name.len() > 256
            || helpers.insert(helper.rva, helper.clone()).is_some()
        {
            return refused(AotObjectModelRefusal::HelperEvidenceAmbiguous, type_layouts);
        }
    }
    if attribution.method_table_references.len() > MAX_METHOD_TABLES {
        return refused(
            AotObjectModelRefusal::MethodTableLimitExceeded,
            type_layouts,
        );
    }
    let mut method_tables: BTreeMap<u32, u32> = BTreeMap::new();
    for reference in &attribution.method_table_references {
        if method_tables
            .insert(reference.method_table_rva, reference.type_record_offset)
            .is_some_and(|owner: u32| owner != reference.type_record_offset)
        {
            return refused(
                AotObjectModelRefusal::MethodTableEvidenceAmbiguous,
                type_layouts,
            );
        }
    }
    if !image.starts_with(b"MZ") {
        return refused(AotObjectModelRefusal::UnsupportedContainer, type_layouts);
    }
    let pe = match crate::pe::parse(image) {
        Ok(pe) if pe.bitness == PeBitness::Pe32Plus && pe.machine == AMD64_MACHINE => pe,
        _ => return refused(AotObjectModelRefusal::UnsupportedContainer, type_layouts),
    };
    let mut total = 0usize;
    let mut stores = Vec::new();
    let mut calls = Vec::new();
    let mut type_references = Vec::new();
    let mut field_initializers = Vec::new();
    let mut reference_stores = Vec::new();
    for evidence in method_evidence {
        let range = AotCodeRange {
            start_rva: evidence.start_rva,
            end_rva: evidence.end_rva,
        };
        let Some(length_u32) = range.end_rva.checked_sub(range.start_rva) else {
            return refused(AotObjectModelRefusal::MethodRangeInvalid, type_layouts);
        };
        let length = match usize::try_from(length_u32) {
            Ok(0) | Err(_) => {
                return refused(AotObjectModelRefusal::MethodRangeInvalid, type_layouts);
            }
            Ok(length) if length > MAX_METHOD_BYTES => {
                return refused(AotObjectModelRefusal::MethodRangeExceeded, type_layouts);
            }
            Ok(length) => length,
        };
        total = match total.checked_add(length) {
            Some(total) if total <= MAX_TOTAL_METHOD_BYTES => total,
            _ => {
                return refused(
                    AotObjectModelRefusal::AggregateMethodBytesExceeded,
                    type_layouts,
                );
            }
        };
        let Some(bytes) = pe.slice_exact_file_backed_rva(image, range.start_rva, length) else {
            return refused(AotObjectModelRefusal::MethodRangeInvalid, type_layouts);
        };
        let instructions: Vec<DisasmInsn> =
            match disassemble(Arch::X86_64, u64::from(range.start_rva), bytes) {
                Ok(instructions) => instructions,
                Err(_) => return refused(AotObjectModelRefusal::DisassemblyFailed, type_layouts),
            };
        for (index, instruction) in instructions.iter().enumerate() {
            let previous: Option<&DisasmInsn> = index
                .checked_sub(1)
                .and_then(|previous| instructions.get(previous));
            let prior: Option<&[u8]> = previous.map(|previous| previous.bytes.as_slice());
            let Ok(rva): Result<u32, std::num::TryFromIntError> =
                u32::try_from(instruction.address)
            else {
                return refused(AotObjectModelRefusal::MethodRangeInvalid, type_layouts);
            };
            if instruction.mnemonic == "call"
                && instruction.bytes.first() == Some(&0xe8)
                && let Some(helper) =
                    call_target(rva, &instruction.bytes, 0).and_then(|target| helpers.get(&target))
            {
                if calls.len() == MAX_HELPER_CALLS {
                    return refused(AotObjectModelRefusal::HelperCallLimitExceeded, type_layouts);
                }
                calls.push(AotObjectHelperCall {
                    method_record_offset: evidence.method_record_offset,
                    call_rva: rva,
                    helper: helper.clone(),
                });
            }
            if instruction.mnemonic == "lea"
                && let Some((method_table_rva, type_record_offset)) =
                    method_table_target(rva, &instruction.bytes)
                        .and_then(|target: u32| method_tables.get_key_value(&target))
            {
                if type_references.len() == MAX_TYPE_REFERENCES {
                    return refused(
                        AotObjectModelRefusal::TypeReferenceLimitExceeded,
                        type_layouts,
                    );
                }
                type_references.push(AotObjectTypeReference {
                    method_record_offset: evidence.method_record_offset,
                    instruction_rva: rva,
                    type_record_offset: *type_record_offset,
                    method_table_rva: *method_table_rva,
                });
            }
            if evidence.constructor
                && instruction.mnemonic == "mov"
                && let Some((store_offset, value)) = field_initializer(&instruction.bytes, prior)
            {
                let parts: Vec<(u32, AotObjectConstant)> = split_initializer(
                    offsets_by_type.get(&evidence.type_record_offset),
                    store_offset,
                    value,
                );
                for (field_offset, value) in parts {
                    if field_initializers.len() == MAX_FIELD_INITIALIZERS {
                        return refused(
                            AotObjectModelRefusal::FieldInitializerLimitExceeded,
                            type_layouts,
                        );
                    }
                    let field = fields_by_offset.get(&(evidence.type_record_offset, field_offset));
                    field_initializers.push(AotObjectFieldInitializer {
                        type_record_offset: evidence.type_record_offset,
                        method_record_offset: evidence.method_record_offset,
                        store_rva: rva,
                        field_offset,
                        value,
                        field_name: field.map(|(_record_offset, name, _field_type)| name.clone()),
                        field_type: field.map(|(_record_offset, _name, field_type)| *field_type),
                    });
                }
            }
            if evidence.constructor
                && instruction.mnemonic == "mov"
                && let Some((field_offset, object_rva)) =
                    reference_store(&instruction.bytes, previous)
            {
                if reference_stores.len() == MAX_REFERENCE_STORES {
                    return refused(AotObjectModelRefusal::FieldStoreLimitExceeded, type_layouts);
                }
                let field = fields_by_offset.get(&(evidence.type_record_offset, field_offset));
                reference_stores.push(AotObjectReferenceStore {
                    type_record_offset: evidence.type_record_offset,
                    method_record_offset: evidence.method_record_offset,
                    store_rva: rva,
                    field_offset,
                    object_rva,
                    field_name: field.map(|(_record_offset, name, _field_type)| name.clone()),
                    field_type: field.map(|(_record_offset, _name, field_type)| *field_type),
                });
            }
            let Some((width, source_register, field_offset)) = field_store(&instruction.bytes, 0)
            else {
                continue;
            };
            if stores.len() == MAX_FIELD_STORES {
                return refused(AotObjectModelRefusal::FieldStoreLimitExceeded, type_layouts);
            }
            let field = fields_by_offset.get(&(evidence.type_record_offset, field_offset));
            stores.push(AotObjectFieldStore {
                type_record_offset: evidence.type_record_offset,
                method_record_offset: evidence.method_record_offset,
                store_rva: rva,
                field_offset,
                width,
                source_register,
                field_name: field.map(|(_record_offset, name, _field_type)| name.clone()),
                field_type: field.map(|(_record_offset, _name, field_type)| *field_type),
            });
        }
    }
    AotObjectModel {
        status: AotObjectModelStatus::Recovered,
        type_layouts,
        field_stores: stores,
        helper_calls: calls,
        type_references,
        field_initializers,
        reference_stores,
        frozen_strings: Vec::new(),
    }
}
fn reference_store(bytes: &[u8], previous: Option<&DisasmInsn>) -> Option<(u32, u32)> {
    let [0x48, 0x89, ..] = bytes else {
        return None;
    };
    let operand: ThisOperand = this_operand(bytes, 2)?;
    if operand.end != bytes.len() || operand.register != 0 {
        return None;
    }
    let previous: &DisasmInsn = previous?;
    let [0x48, 0x8d, 0x05, a, b, c, d] = previous.bytes.as_slice() else {
        return None;
    };
    let lea_rva: u32 = u32::try_from(previous.address).ok()?;
    let target: i64 = i64::from(lea_rva.checked_add(7)?)
        .checked_add(i64::from(i32::from_le_bytes([*a, *b, *c, *d])))?;
    Some((operand.offset, u32::try_from(target).ok()?))
}
fn read_u32_rva(image: &[u8], pe: &crate::pe::PeImage, rva: u32) -> Option<u32> {
    let bytes: [u8; 4] = pe
        .slice_exact_file_backed_rva(image, rva, 4)?
        .try_into()
        .ok()?;
    Some(u32::from_le_bytes(bytes))
}
fn read_u64_rva(image: &[u8], pe: &crate::pe::PeImage, rva: u32) -> Option<u64> {
    let bytes: [u8; 8] = pe
        .slice_exact_file_backed_rva(image, rva, 8)?
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}
fn string_method_table(image: &[u8], pe: &crate::pe::PeImage, method_table_rva: u32) -> bool {
    let Some(flags): Option<u32> = read_u32_rva(image, pe, method_table_rva) else {
        return false;
    };
    flags & METHOD_TABLE_HAS_COMPONENT_SIZE != 0
        && flags & 0xFFFF == STRING_COMPONENT_SIZE
        && (flags & METHOD_TABLE_ELEMENT_TYPE_MASK) >> METHOD_TABLE_ELEMENT_TYPE_SHIFT
            == METHOD_TABLE_ELEMENT_TYPE_CLASS
        && flags & METHOD_TABLE_KIND_MASK == 0
}
fn frozen_string(
    image: &[u8],
    pe: &crate::pe::PeImage,
    region: AotCodeRange,
    object_rva: u32,
) -> Option<(u32, String)> {
    if object_rva < region.start_rva || object_rva >= region.end_rva {
        return None;
    }
    let method_table_va: u64 = read_u64_rva(image, pe, object_rva)?;
    let method_table_rva: u32 = u32::try_from(method_table_va.checked_sub(pe.image_base)?).ok()?;
    if !string_method_table(image, pe, method_table_rva) {
        return None;
    }
    let length: u32 = read_u32_rva(
        image,
        pe,
        object_rva.checked_add(FROZEN_STRING_LENGTH_OFFSET)?,
    )?;
    if length > MAX_FROZEN_STRING_CHARS {
        return None;
    }
    let chars_rva: u32 = object_rva.checked_add(FROZEN_STRING_CHARS_OFFSET)?;
    let byte_length: u32 = length.checked_mul(2)?.checked_add(2)?;
    if chars_rva.checked_add(byte_length)? > region.end_rva {
        return None;
    }
    let bytes: &[u8] =
        pe.slice_exact_file_backed_rva(image, chars_rva, usize::try_from(byte_length).ok()?)?;
    let (units, terminator): (&[u8], &[u8]) = bytes.split_at(bytes.len().checked_sub(2)?);
    if terminator != [0, 0] {
        return None;
    }
    let decoded: Vec<u16> = units
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect();
    let value: String = char::decode_utf16(decoded)
        .collect::<Result<String, _>>()
        .ok()?;
    Some((method_table_rva, value))
}
pub fn resolve_frozen_strings(
    image: &[u8],
    region: AotCodeRange,
    stores: &[AotObjectReferenceStore],
) -> Vec<AotObjectFrozenString> {
    if !image.starts_with(b"MZ") || region.start_rva >= region.end_rva {
        return Vec::new();
    }
    let Ok(pe) = crate::pe::parse(image) else {
        return Vec::new();
    };
    if pe.bitness != PeBitness::Pe32Plus || pe.machine != AMD64_MACHINE {
        return Vec::new();
    }
    let mut resolved: Vec<AotObjectFrozenString> = Vec::new();
    let mut method_tables: BTreeSet<u32> = BTreeSet::new();
    for store in stores {
        let Some((method_table_rva, value)) = frozen_string(image, &pe, region, store.object_rva)
        else {
            continue;
        };
        method_tables.insert(method_table_rva);
        resolved.push(AotObjectFrozenString {
            type_record_offset: store.type_record_offset,
            store_rva: store.store_rva,
            field_offset: store.field_offset,
            object_rva: store.object_rva,
            method_table_rva,
            value,
            field_name: store.field_name.clone(),
        });
    }
    if method_tables.len() > 1 {
        return Vec::new();
    }
    resolved
}
