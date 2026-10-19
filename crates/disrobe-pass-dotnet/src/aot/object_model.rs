use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{AotCodeRange, AotMetadataAttribution, AotTypeLayout, AotTypeSignature};
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectMethodEvidence {
    pub type_record_offset: u32,
    pub method_record_offset: u32,
    pub start_rva: u32,
    pub end_rva: u32,
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
    pub method_record_offset: u32,
    pub store_rva: u32,
    pub field_offset: u8,
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
    pub method_record_offset: u32,
    pub call_rva: u32,
    pub helper: AotObjectHelperEvidence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectTypeReference {
    pub method_record_offset: u32,
    pub instruction_rva: u32,
    pub type_record_offset: u32,
    pub method_table_rva: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AotObjectConstant {
    Byte(u8),
    Dword(u32),
    Qword(u64),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotObjectFieldInitializer {
    pub type_record_offset: u32,
    pub method_record_offset: u32,
    pub store_rva: u32,
    pub field_offset: u8,
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
    }
}
fn field_store(bytes: &[u8], at: usize) -> Option<(AotObjectStoreWidth, u8, u8)> {
    let first = *bytes.get(at)?;
    let (width, modrm_at, offset_at) = match first {
        0x48 if bytes.get(at.checked_add(1)?) == Some(&0x89) => (
            AotObjectStoreWidth::Pointer,
            at.checked_add(2)?,
            at.checked_add(3)?,
        ),
        0x89 => (
            AotObjectStoreWidth::Dword,
            at.checked_add(1)?,
            at.checked_add(2)?,
        ),
        _ => return None,
    };
    let modrm = *bytes.get(modrm_at)?;
    let offset = *bytes.get(offset_at)?;
    (modrm & 0b1100_0111 == 0b0100_0001 && offset != 0).then_some((width, (modrm >> 3) & 7, offset))
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
fn field_initializer(bytes: &[u8]) -> Option<(u8, AotObjectConstant)> {
    match bytes {
        [0xc6, 0x41, offset, value, ..] if *offset != 0 => {
            Some((*offset, AotObjectConstant::Byte(*value)))
        }
        [0xc7, 0x41, offset, a, b, c, d, ..] if *offset != 0 => Some((
            *offset,
            AotObjectConstant::Dword(u32::from_le_bytes([*a, *b, *c, *d])),
        )),
        [0x48, 0xc7, 0x41, offset, a, b, c, d, ..] if *offset != 0 => {
            let value: i64 = i64::from(i32::from_le_bytes([*a, *b, *c, *d]));
            Some((*offset, AotObjectConstant::Qword(value as u64)))
        }
        _ => None,
    }
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
    let constructors: BTreeSet<u32> = attribution
        .methods
        .iter()
        .filter(|method| method.name == ".ctor")
        .map(|method| method.record_offset)
        .collect();
    let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(method_evidence.len());
    for evidence in method_evidence {
        if evidence.start_rva >= evidence.end_rva
            || !known.contains(&(evidence.type_record_offset, evidence.method_record_offset))
        {
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
        for instruction in instructions {
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
            if constructors.contains(&evidence.method_record_offset)
                && instruction.mnemonic == "mov"
                && let Some((field_offset, value)) = field_initializer(&instruction.bytes)
            {
                if field_initializers.len() == MAX_FIELD_INITIALIZERS {
                    return refused(
                        AotObjectModelRefusal::FieldInitializerLimitExceeded,
                        type_layouts,
                    );
                }
                let field =
                    fields_by_offset.get(&(evidence.type_record_offset, u32::from(field_offset)));
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
            let Some((width, source_register, field_offset)) = field_store(&instruction.bytes, 0)
            else {
                continue;
            };
            if stores.len() == MAX_FIELD_STORES {
                return refused(AotObjectModelRefusal::FieldStoreLimitExceeded, type_layouts);
            }
            let field =
                fields_by_offset.get(&(evidence.type_record_offset, u32::from(field_offset)));
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
    }
}
