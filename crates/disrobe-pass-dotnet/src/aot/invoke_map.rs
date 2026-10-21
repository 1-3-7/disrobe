use disrobe_bytes::read_i32_le_at;
use object::read::File as ObjFile;
use object::{Object as _, ObjectSection as _, SectionKind};
use serde::{Deserialize, Serialize};

use super::metadata_records::{
    AotMethod, AotMethodSignature, AotMethodTableReference, AotOwnedEntrypoint,
    AotRuntimeFieldLayout, AotType,
};
use super::native_hashtable;
use super::{
    AotContainer, AotSection, ReadyToRunHeader, address_range_is_inside, container_section_bytes,
    open_container, unique_section,
};

const INVOKE_MAP_SECTION_ID: i32 = 306;
const COMMON_FIXUPS_SECTION_ID: i32 = 308;
const HAS_METADATA_HANDLE: u32 = 0x04;
const IS_GENERIC_METHOD: u32 = 0x02;
const REQUIRES_INST_ARG: u32 = 0x10;
const HAS_ENTRYPOINT: u32 = 0x20;
const IS_UNIVERSAL_CANONICAL_ENTRY: u32 = 0x40;
const NEEDS_PARAMETER_INTERPRETATION: u32 = 0x80;
const INVOKE_FLAGS_MASK: u32 = 0x70ff;
const MAX_INVOKE_MAP_BYTES: usize = 16 * 1024 * 1024;
const MAX_INVOKE_MAP_ENTRIES: usize = 1_048_576;
const MAX_GENERIC_ARGUMENTS: usize = 1_024;
const MAX_RETAINED_CONTEXT_WORDS: usize = 4 * 1024 * 1024;
const MAX_REFUSAL_TEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotInvokeMapRefusal {
    pub entry_offset: u32,
    pub method_record_offset: Option<u32>,
    pub method_name: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeMapLayout {
    DictionaryTail,
    FlaggedMetadataOrName,
    EmbeddedMetadataOnly,
}

impl InvokeMapLayout {
    const fn for_header(header: &ReadyToRunHeader) -> Self {
        match (header.major_version, header.minor_version) {
            (16, 0) => Self::EmbeddedMetadataOnly,
            (8, 0) => Self::DictionaryTail,
            _ => Self::FlaggedMetadataOrName,
        }
    }

    const fn allowed_flags(self) -> u32 {
        match self {
            Self::DictionaryTail | Self::FlaggedMetadataOrName => INVOKE_FLAGS_MASK,
            Self::EmbeddedMetadataOnly => {
                INVOKE_FLAGS_MASK & !(HAS_METADATA_HANDLE | IS_UNIVERSAL_CANONICAL_ENTRY)
            }
        }
    }

    const fn has_metadata_offset(self, flags: u32) -> bool {
        match self {
            Self::DictionaryTail | Self::FlaggedMetadataOrName => flags & HAS_METADATA_HANDLE != 0,
            Self::EmbeddedMetadataOnly => true,
        }
    }

    const fn generic_tail(self, flags: u32) -> GenericTail {
        let universal: bool = flags & IS_UNIVERSAL_CANONICAL_ENTRY != 0;
        let requires_instantiation: bool = flags & REQUIRES_INST_ARG != 0;
        match self {
            Self::EmbeddedMetadataOnly => GenericTail {
                leading_reference: false,
                argument_sequence: true,
            },
            Self::FlaggedMetadataOrName => GenericTail {
                leading_reference: requires_instantiation,
                argument_sequence: !universal,
            },
            Self::DictionaryTail => {
                let sequence: bool =
                    !universal && (!requires_instantiation || flags & HAS_ENTRYPOINT == 0);
                GenericTail {
                    leading_reference: !sequence,
                    argument_sequence: sequence,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct GenericTail {
    leading_reference: bool,
    argument_sequence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InvokeIdentity {
    method_offset: u32,
    declaring_type_index: u32,
    generic_context: Vec<u32>,
}

#[derive(Debug, Clone)]
struct InvokeMapping {
    entry_offset: usize,
    identity: InvokeIdentity,
    method_index: usize,
    entrypoint_rva: Option<u32>,
}

struct EntryRefusal {
    entry_offset: usize,
    method_index: Option<usize>,
    error: crate::error::Error,
}

struct CommonFixups<'a, 'b> {
    bytes: &'b [u8],
    section_start: u64,
    address_base: u64,
    file: &'b ObjFile<'a, &'a [u8]>,
}

#[derive(Debug, Clone, Copy)]
enum FixupTargetRole {
    Entrypoint,
    RuntimeType,
}

fn invalid(at: usize, reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidAotInvokeMap {
        offset: u32::try_from(at).map_or(u32::MAX, |value: u32| value),
        reason,
    }
}

fn decode_unsigned(bytes: &[u8], at: &mut usize) -> crate::error::Result<u32> {
    native_hashtable::decode_unsigned(bytes, at, invalid)
}

fn entry_offsets(bytes: &[u8]) -> crate::error::Result<Vec<usize>> {
    if bytes.len() > MAX_INVOKE_MAP_BYTES {
        return Err(invalid(0, "invoke-map blob exceeds parser byte limit"));
    }
    native_hashtable::entry_offsets(bytes, MAX_INVOKE_MAP_ENTRIES, invalid)
}

fn resolve_fixup<'a>(
    bytes: &[u8],
    section_start: u64,
    address_base: u64,
    file: &ObjFile<'a, &'a [u8]>,
    index: u32,
) -> crate::error::Result<u32> {
    let (slot_delta, target): (usize, u64) =
        resolve_fixup_target(bytes, section_start, index, invalid)?;
    let in_text: bool = file.sections().any(|section| {
        if section.kind() != SectionKind::Text {
            return false;
        }
        let Some((_file_offset, file_size)): Option<(u64, u64)> = section.file_range() else {
            return false;
        };
        let start: u64 = section.address();
        let Some(end): Option<u64> = start.checked_add(file_size) else {
            return false;
        };
        address_range_is_inside(target, target, start, end)
    });
    if !in_text {
        return Err(invalid(
            slot_delta,
            "common-fixup entrypoint does not resolve into executable code",
        ));
    }
    fixup_target_rva(
        target,
        address_base,
        slot_delta,
        FixupTargetRole::Entrypoint,
        invalid,
    )
}

fn resolve_fixup_target(
    bytes: &[u8],
    section_start: u64,
    index: u32,
    invalid: native_hashtable::Invalid,
) -> crate::error::Result<(usize, u64)> {
    let slot_delta: usize = usize::try_from(index)
        .map_err(|_: std::num::TryFromIntError| {
            invalid(0, "common-fixup index does not fit usize")
        })?
        .checked_mul(4)
        .ok_or_else(|| invalid(0, "common-fixup slot offset overflowed"))?;
    let delta: i32 =
        read_i32_le_at(bytes, slot_delta).map_err(|_: disrobe_bytes::ByteReadError| {
            invalid(slot_delta, "common-fixup slot is truncated")
        })?;
    let slot_address: u64 = section_start
        .checked_add(
            u64::try_from(slot_delta).map_err(|_: std::num::TryFromIntError| {
                invalid(slot_delta, "common-fixup slot offset does not fit u64")
            })?,
        )
        .ok_or_else(|| invalid(slot_delta, "common-fixup slot address overflowed"))?;
    let target: u64 = if delta >= 0 {
        slot_address.checked_add(delta as u64)
    } else {
        slot_address.checked_sub(u64::from(delta.unsigned_abs()))
    }
    .ok_or_else(|| invalid(slot_delta, "common-fixup target address overflowed"))?;
    Ok((slot_delta, target))
}

fn fixup_target_rva(
    target: u64,
    address_base: u64,
    slot_delta: usize,
    role: FixupTargetRole,
    invalid: native_hashtable::Invalid,
) -> crate::error::Result<u32> {
    let rva: u64 = target.checked_sub(address_base).ok_or_else(|| {
        invalid(
            slot_delta,
            match role {
                FixupTargetRole::Entrypoint => "common-fixup entrypoint precedes the image base",
                FixupTargetRole::RuntimeType => "common-fixup runtime type precedes the image base",
            },
        )
    })?;
    u32::try_from(rva).map_err(|_: std::num::TryFromIntError| {
        invalid(
            slot_delta,
            match role {
                FixupTargetRole::Entrypoint => "entrypoint RVA does not fit u32",
                FixupTargetRole::RuntimeType => "runtime type RVA does not fit u32",
            },
        )
    })
}

pub(super) fn resolve_runtime_type_fixup<'a>(
    bytes: &[u8],
    section_start: u64,
    address_base: u64,
    file: &ObjFile<'a, &'a [u8]>,
    index: u32,
    invalid: native_hashtable::Invalid,
) -> crate::error::Result<u32> {
    let (slot_delta, target): (usize, u64) =
        resolve_fixup_target(bytes, section_start, index, invalid)?;
    let in_data: bool = file.sections().any(|section| {
        if section.kind() == SectionKind::Text {
            return false;
        }
        let Some((_file_offset, file_size)): Option<(u64, u64)> = section.file_range() else {
            return false;
        };
        if file_size == 0 {
            return false;
        }
        let start: u64 = section.address();
        let Some(end): Option<u64> = start.checked_add(file_size) else {
            return false;
        };
        address_range_is_inside(target, target, start, end)
    });
    if !in_data {
        return Err(invalid(
            slot_delta,
            "common-fixup runtime type does not resolve into file-backed non-executable storage",
        ));
    }
    fixup_target_rva(
        target,
        address_base,
        slot_delta,
        FixupTargetRole::RuntimeType,
        invalid,
    )
}

fn read_generic_tail(
    layout: InvokeMapLayout,
    flags: u32,
    bytes: &[u8],
    cursor: &mut usize,
    arity: usize,
    context: &mut Vec<u32>,
) -> crate::error::Result<()> {
    let tail: GenericTail = layout.generic_tail(flags);
    if tail.leading_reference {
        context.push(decode_unsigned(bytes, cursor)?);
    }
    if !tail.argument_sequence {
        return Ok(());
    }
    let count_at: usize = *cursor;
    let count: usize = usize::try_from(decode_unsigned(bytes, cursor)?).map_err(
        |_: std::num::TryFromIntError| {
            invalid(count_at, "generic argument count does not fit usize")
        },
    )?;
    if count > MAX_GENERIC_ARGUMENTS {
        return Err(invalid(
            count_at,
            "generic argument count exceeds parser limit",
        ));
    }
    if count != arity {
        return Err(invalid(
            count_at,
            "generic argument count differs from the method signature",
        ));
    }
    context
        .try_reserve_exact(count)
        .map_err(|_: std::collections::TryReserveError| {
            invalid(count_at, "generic invoke-map allocation failed")
        })?;
    for _ in 0..count {
        context.push(decode_unsigned(bytes, cursor)?);
    }
    Ok(())
}

fn decode_entry(
    layout: InvokeMapLayout,
    bytes: &[u8],
    offset: usize,
    method_indices: &[(u32, usize)],
    methods: &[AotMethod],
    fixups: &CommonFixups<'_, '_>,
) -> Result<Option<InvokeMapping>, EntryRefusal> {
    let unnamed = |error: crate::error::Error| EntryRefusal {
        entry_offset: offset,
        method_index: None,
        error,
    };
    let mut cursor: usize = offset;
    let flags: u32 = decode_unsigned(bytes, &mut cursor).map_err(unnamed)?;
    if flags & !layout.allowed_flags() != 0 {
        return Err(unnamed(invalid(
            offset,
            "invoke-map entry uses unsupported flags",
        )));
    }
    let method_offset: u32 = decode_unsigned(bytes, &mut cursor).map_err(unnamed)?;
    let declaring_type_index: u32 = decode_unsigned(bytes, &mut cursor).map_err(unnamed)?;
    let entrypoint_index: Option<u32> = if flags & HAS_ENTRYPOINT == 0 {
        None
    } else {
        Some(decode_unsigned(bytes, &mut cursor).map_err(unnamed)?)
    };
    if !layout.has_metadata_offset(flags) {
        return Ok(None);
    }
    let method_index: usize = method_indices
        .binary_search_by_key(&method_offset, |(record_offset, _index): &(u32, usize)| {
            *record_offset
        })
        .ok()
        .and_then(|position: usize| method_indices.get(position))
        .map(|(_record_offset, index): &(u32, usize)| *index)
        .ok_or_else(|| {
            unnamed(invalid(
                offset,
                "invoke-map metadata handle has no recovered method record",
            ))
        })?;
    let named = |error: crate::error::Error| EntryRefusal {
        entry_offset: offset,
        method_index: Some(method_index),
        error,
    };
    let method: &AotMethod = methods.get(method_index).ok_or_else(|| {
        named(invalid(
            offset,
            "invoke-map method index is outside recovered methods",
        ))
    })?;
    if flags & NEEDS_PARAMETER_INTERPRETATION == 0 {
        let _invoke_stub_index: u32 = decode_unsigned(bytes, &mut cursor).map_err(named)?;
    }
    let mut generic_context: Vec<u32> =
        vec![flags & (IS_GENERIC_METHOD | REQUIRES_INST_ARG | IS_UNIVERSAL_CANONICAL_ENTRY)];
    if flags & IS_GENERIC_METHOD != 0 {
        let arity: usize = method
            .signature
            .as_ref()
            .ok_or_else(|| {
                named(invalid(
                    offset,
                    "generic invoke-map method has no signature",
                ))
            })
            .and_then(|signature: &AotMethodSignature| {
                usize::try_from(signature.generic_parameter_count).map_err(
                    |_: std::num::TryFromIntError| {
                        named(invalid(
                            offset,
                            "generic invoke-map arity does not fit usize",
                        ))
                    },
                )
            })?;
        read_generic_tail(
            layout,
            flags,
            bytes,
            &mut cursor,
            arity,
            &mut generic_context,
        )
        .map_err(named)?;
    }
    let entrypoint_rva: Option<u32> = entrypoint_index
        .map(|index: u32| {
            resolve_fixup(
                fixups.bytes,
                fixups.section_start,
                fixups.address_base,
                fixups.file,
                index,
            )
        })
        .transpose()
        .map_err(named)?;
    Ok(Some(InvokeMapping {
        entry_offset: offset,
        identity: InvokeIdentity {
            method_offset,
            declaring_type_index,
            generic_context,
        },
        method_index,
        entrypoint_rva,
    }))
}

fn retain_context_words(
    retained: &mut usize,
    words: usize,
    offset: usize,
) -> crate::error::Result<()> {
    let total: usize = retained
        .checked_add(words)
        .filter(|total: &usize| *total <= MAX_RETAINED_CONTEXT_WORDS)
        .ok_or_else(|| invalid(offset, "invoke-map retained context quota exceeded"))?;
    *retained = total;
    Ok(())
}

fn refusal_record(
    methods: &[AotMethod],
    refusal: EntryRefusal,
    retained_text_bytes: &mut usize,
) -> crate::error::Result<AotInvokeMapRefusal> {
    let method: Option<&AotMethod> = refusal
        .method_index
        .and_then(|index: usize| methods.get(index));
    let reason: String = refusal.error.to_string();
    let total: usize = retained_text_bytes
        .checked_add(reason.len())
        .and_then(|total: usize| {
            total.checked_add(method.map_or(0, |method: &AotMethod| method.name.len()))
        })
        .filter(|total: &usize| *total <= MAX_REFUSAL_TEXT_BYTES)
        .ok_or_else(|| {
            invalid(
                refusal.entry_offset,
                "invoke-map refusal text quota exceeded",
            )
        })?;
    *retained_text_bytes = total;
    Ok(AotInvokeMapRefusal {
        entry_offset: u32::try_from(refusal.entry_offset).map_or(u32::MAX, |value: u32| value),
        method_record_offset: method.map(|method: &AotMethod| method.record_offset),
        method_name: method.map(|method: &AotMethod| method.name.clone()),
        reason,
    })
}

pub(super) struct InvokeMapAttachment {
    pub(super) refusals: Vec<AotInvokeMapRefusal>,
    pub(super) method_table_references: Vec<AotMethodTableReference>,
    pub(super) owned_entrypoints: Vec<AotOwnedEntrypoint>,
}

pub(super) fn attach_invoke_map_entrypoints(
    image: &[u8],
    header: &ReadyToRunHeader,
    types: &[AotType],
    runtime_field_layouts: &[AotRuntimeFieldLayout],
    methods: &mut [AotMethod],
) -> crate::error::Result<InvokeMapAttachment> {
    attach_invoke_map(image, header, Some(types), runtime_field_layouts, methods)
}

fn attach_invoke_map(
    image: &[u8],
    header: &ReadyToRunHeader,
    types: Option<&[AotType]>,
    runtime_field_layouts: &[AotRuntimeFieldLayout],
    methods: &mut [AotMethod],
) -> crate::error::Result<InvokeMapAttachment> {
    let layout: InvokeMapLayout = InvokeMapLayout::for_header(header);
    let Some(invoke_section): Option<&AotSection> =
        unique_section(header, INVOKE_MAP_SECTION_ID, invalid)?
    else {
        return Ok(InvokeMapAttachment {
            refusals: Vec::new(),
            method_table_references: Vec::new(),
            owned_entrypoints: Vec::new(),
        });
    };
    let fixups_section: &AotSection = unique_section(header, COMMON_FIXUPS_SECTION_ID, invalid)?
        .ok_or_else(|| invalid(0, "invoke map has no common-fixups section"))?;
    let container: AotContainer<'_> = open_container(image)?;
    let invoke_bytes: &[u8] = container_section_bytes(image, &container, invoke_section, invalid)?;
    let fixups_bytes: &[u8] = container_section_bytes(image, &container, fixups_section, invalid)?;
    if fixups_bytes.len() > MAX_INVOKE_MAP_BYTES {
        return Err(invalid(0, "common-fixups blob exceeds parser byte limit"));
    }
    if !fixups_bytes.len().is_multiple_of(4) {
        return Err(invalid(
            0,
            "common-fixups blob has a partial relative pointer",
        ));
    }
    let fixups: CommonFixups<'_, '_> = CommonFixups {
        bytes: fixups_bytes,
        section_start: container
            .address_base
            .checked_add(u64::from(fixups_section.start_rva))
            .ok_or_else(|| invalid(0, "common-fixups section start address overflowed"))?,
        address_base: container.address_base,
        file: &container.file,
    };
    let mut method_indices: Vec<(u32, usize)> = Vec::new();
    method_indices
        .try_reserve_exact(methods.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for (index, method) in methods.iter().enumerate() {
        method_indices.push((method.record_offset, index));
    }
    method_indices.sort_unstable();
    let mut method_owners: Vec<(u32, u32)> = Vec::new();
    if let Some(types) = types {
        let owner_count: usize = types.iter().try_fold(0usize, |count: usize, type_record| {
            count
                .checked_add(type_record.method_record_offsets.len())
                .filter(|total: &usize| *total <= MAX_INVOKE_MAP_ENTRIES)
                .ok_or_else(|| invalid(0, "metadata method ownership exceeds parser limit"))
        })?;
        method_owners
            .try_reserve_exact(owner_count)
            .map_err(|_| invalid(0, "metadata method ownership allocation failed"))?;
        for type_record in types {
            method_owners.extend(
                type_record
                    .method_record_offsets
                    .iter()
                    .map(|method_offset: &u32| (*method_offset, type_record.record_offset)),
            );
        }
        method_owners.sort_unstable();
        method_owners.dedup();
    }
    let offsets: Vec<usize> = entry_offsets(invoke_bytes)?;
    let mut recovered: Vec<InvokeMapping> = Vec::new();
    recovered
        .try_reserve_exact(offsets.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    let mut refusals: Vec<EntryRefusal> = Vec::new();
    let mut retained_context_words: usize = 0;
    for offset in offsets {
        match decode_entry(
            layout,
            invoke_bytes,
            offset,
            &method_indices,
            methods,
            &fixups,
        ) {
            Ok(Some(mapping)) => {
                retain_context_words(
                    &mut retained_context_words,
                    mapping.identity.generic_context.len(),
                    mapping.entry_offset,
                )?;
                recovered.push(mapping);
            }
            Ok(None) => {}
            Err(refusal) => refusals.push(refusal),
        }
    }
    recovered.sort_unstable_by(|left: &InvokeMapping, right: &InvokeMapping| {
        left.identity
            .cmp(&right.identity)
            .then(left.entry_offset.cmp(&right.entry_offset))
    });
    let mut method_table_references: Vec<AotMethodTableReference> = Vec::new();
    method_table_references
        .try_reserve_exact(recovered.len())
        .map_err(|_| invalid(0, "runtime type reference allocation failed"))?;
    let mut owned_entrypoints: Vec<AotOwnedEntrypoint> = Vec::new();
    owned_entrypoints
        .try_reserve_exact(recovered.len())
        .map_err(|_| invalid(0, "owned entrypoint allocation failed"))?;
    let mut layout_owners: Vec<(u32, u32)> = Vec::new();
    layout_owners
        .try_reserve_exact(runtime_field_layouts.len())
        .map_err(|_| invalid(0, "field layout owner allocation failed"))?;
    layout_owners.extend(runtime_field_layouts.iter().filter_map(
        |layout: &AotRuntimeFieldLayout| {
            layout
                .method_table_rva
                .map(|method_table_rva: u32| (method_table_rva, layout.type_record_offset))
        },
    ));
    layout_owners.sort_unstable();
    layout_owners.dedup();
    if types.is_some() {
        for mapping in &recovered {
            let method: &AotMethod = methods.get(mapping.method_index).ok_or_else(|| {
                invalid(0, "invoke-map method index is outside recovered methods")
            })?;
            let owner_start: usize =
                method_owners.partition_point(|(method_offset, _type_offset): &(u32, u32)| {
                    *method_offset < method.record_offset
                });
            let owner_end: usize =
                method_owners.partition_point(|(method_offset, _type_offset): &(u32, u32)| {
                    *method_offset <= method.record_offset
                });
            let owners: &[(u32, u32)] = method_owners
                .get(owner_start..owner_end)
                .ok_or_else(|| invalid(mapping.entry_offset, "metadata owner range is invalid"))?;
            let resolved: crate::error::Result<u32> = resolve_runtime_type_fixup(
                fixups.bytes,
                fixups.section_start,
                fixups.address_base,
                fixups.file,
                mapping.identity.declaring_type_index,
                invalid,
            );
            let owner_refusal = || EntryRefusal {
                entry_offset: mapping.entry_offset,
                method_index: Some(mapping.method_index),
                error: invalid(
                    mapping.entry_offset,
                    "invoke-map method does not have exactly one metadata owner",
                ),
            };
            let type_record_offset: u32 = match owners {
                [(_method_offset, type_record_offset)] => *type_record_offset,
                [_first, _second, ..] => {
                    let Ok(method_table_rva): &crate::error::Result<u32> = &resolved else {
                        refusals.push(owner_refusal());
                        continue;
                    };
                    let tied_start: usize = layout_owners
                        .partition_point(|(rva, _type_offset): &(u32, u32)| rva < method_table_rva);
                    let tied_end: usize =
                        layout_owners.partition_point(|(rva, _type_offset): &(u32, u32)| {
                            rva <= method_table_rva
                        });
                    let tied: &[(u32, u32)] =
                        layout_owners.get(tied_start..tied_end).ok_or_else(|| {
                            invalid(mapping.entry_offset, "field layout owner range is invalid")
                        })?;
                    let mut candidates = owners.iter().filter(|(_method_offset, type_offset)| {
                        tied.iter()
                            .any(|(_rva, tied_type)| tied_type == type_offset)
                    });
                    let (Some((_method_offset, type_record_offset)), None) =
                        (candidates.next(), candidates.next())
                    else {
                        refusals.push(owner_refusal());
                        continue;
                    };
                    *type_record_offset
                }
                [] => {
                    refusals.push(owner_refusal());
                    continue;
                }
            };
            let method_table_rva: u32 = match resolved {
                Ok(method_table_rva) => method_table_rva,
                Err(error) => {
                    refusals.push(EntryRefusal {
                        entry_offset: mapping.entry_offset,
                        method_index: Some(mapping.method_index),
                        error,
                    });
                    continue;
                }
            };
            method_table_references.push(AotMethodTableReference {
                type_record_offset,
                method_table_rva,
            });
            if mapping.identity.generic_context.as_slice() == [0]
                && let Some(entrypoint_rva) = mapping.entrypoint_rva
            {
                owned_entrypoints.push(AotOwnedEntrypoint {
                    type_record_offset,
                    method_record_offset: method.record_offset,
                    entrypoint_rva,
                });
            }
        }
    }
    method_table_references.sort_unstable();
    method_table_references.dedup();
    owned_entrypoints.sort_unstable();
    owned_entrypoints.dedup();
    let mut entrypoints: Vec<(usize, u32)> = Vec::new();
    entrypoints
        .try_reserve_exact(recovered.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for group in recovered
        .chunk_by(|left: &InvokeMapping, right: &InvokeMapping| left.identity == right.identity)
    {
        let Some(first): Option<&InvokeMapping> = group.first() else {
            continue;
        };
        if group
            .iter()
            .all(|mapping: &InvokeMapping| mapping.entrypoint_rva == first.entrypoint_rva)
        {
            if let Some(entrypoint_rva) = first.entrypoint_rva {
                entrypoints.push((first.method_index, entrypoint_rva));
            }
            continue;
        }
        for mapping in group {
            refusals.push(EntryRefusal {
                entry_offset: mapping.entry_offset,
                method_index: Some(mapping.method_index),
                error: invalid(
                    mapping.entry_offset,
                    "invoke map gives one method identity different entrypoints",
                ),
            });
        }
    }
    refusals.sort_by_key(|refusal: &EntryRefusal| refusal.entry_offset);
    let mut records: Vec<AotInvokeMapRefusal> = Vec::new();
    records
        .try_reserve_exact(refusals.len())
        .map_err(|_| invalid(0, "invoke-map refusal allocation failed"))?;
    let mut retained_text_bytes: usize = 0;
    for refusal in refusals {
        records.push(refusal_record(methods, refusal, &mut retained_text_bytes)?);
    }
    entrypoints.sort_unstable();
    entrypoints.dedup();
    for group in entrypoints.chunk_by(|left: &(usize, u32), right: &(usize, u32)| left.0 == right.0)
    {
        let Some((method_index, entrypoint_rva)): Option<&(usize, u32)> = group.first() else {
            continue;
        };
        let method: &mut AotMethod = methods
            .get_mut(*method_index)
            .ok_or_else(|| invalid(0, "invoke-map method index is outside recovered methods"))?;
        if let [_single] = group {
            method.entrypoint_rva = Some(*entrypoint_rva);
            continue;
        }
        let mut instantiations: Vec<u32> = Vec::new();
        instantiations
            .try_reserve_exact(group.len())
            .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
        instantiations.extend(group.iter().map(|(_index, rva): &(usize, u32)| *rva));
        method.instantiation_entrypoint_rvas = instantiations;
    }
    Ok(InvokeMapAttachment {
        refusals: records,
        method_table_references,
        owned_entrypoints,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use disrobe_bytes::{read_u16_le_at, read_u32_le_at};
    use object::{Object as _, ObjectSection as _};

    use super::super::container_address_base;
    use super::*;

    const IMAGE: &[u8] =
        include_bytes!("../../tests/fixtures/native_aot/invoke_map_net9_x86_64.exe");
    const METADATA_ENTRY: u32 =
        HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION;

    #[derive(Clone)]
    struct TestEntry {
        flags: u32,
        method_reference: u32,
        declaring_type_index: u32,
        entrypoint_index: u32,
        tail: Vec<u32>,
    }

    impl TestEntry {
        fn metadata(
            method_reference: u32,
            declaring_type_index: u32,
            entrypoint_index: u32,
        ) -> Self {
            Self {
                flags: METADATA_ENTRY,
                method_reference,
                declaring_type_index,
                entrypoint_index,
                tail: Vec::new(),
            }
        }

        fn generic(
            method_reference: u32,
            entrypoint_index: u32,
            count: u32,
            arguments: &[u32],
        ) -> Self {
            let mut tail: Vec<u32> = vec![count];
            tail.extend_from_slice(arguments);
            Self {
                flags: METADATA_ENTRY | IS_GENERIC_METHOD,
                method_reference,
                declaring_type_index: 0,
                entrypoint_index,
                tail,
            }
        }
    }

    fn encode_unsigned(value: u32) -> Vec<u8> {
        if value < 1 << 7 {
            return vec![(value << 1) as u8];
        }
        if value < 1 << 14 {
            return vec![((value << 2) | 1) as u8, (value >> 6) as u8];
        }
        if value < 1 << 21 {
            return vec![
                ((value << 3) | 3) as u8,
                (value >> 5) as u8,
                (value >> 13) as u8,
            ];
        }
        if value < 1 << 28 {
            return vec![
                ((value << 4) | 7) as u8,
                (value >> 4) as u8,
                (value >> 12) as u8,
                (value >> 20) as u8,
            ];
        }
        let mut encoded: Vec<u8> = vec![15];
        encoded.extend_from_slice(&value.to_le_bytes());
        encoded
    }

    fn invoke_blob(entries: &[TestEntry]) -> Vec<u8> {
        let bucket_end: usize = 3 + entries.len() * 2;
        let mut vertices: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut vertex: Vec<u8> = encode_unsigned(entry.flags);
            vertex.extend(encode_unsigned(entry.method_reference));
            vertex.extend(encode_unsigned(entry.declaring_type_index));
            vertex.extend(encode_unsigned(entry.entrypoint_index));
            for value in &entry.tail {
                vertex.extend(encode_unsigned(*value));
            }
            vertices.push(vertex);
        }
        let mut blob: Vec<u8> = vec![0, 2, (bucket_end - 1) as u8];
        let mut vertex_offset: usize = bucket_end;
        for (index, vertex) in vertices.iter().enumerate() {
            let relative_at: usize = 4 + index * 2;
            let delta: usize = vertex_offset - relative_at;
            assert!(delta < 64);
            blob.push(0);
            blob.push((delta << 1) as u8);
            vertex_offset += vertex.len();
        }
        for vertex in vertices {
            blob.extend(vertex);
        }
        blob
    }

    fn section_file_offset(image: &[u8], section: &AotSection) -> crate::error::Result<usize> {
        let file: ObjFile<'_, &[u8]> = ObjFile::parse(image).map_err(|error: object::Error| {
            crate::error::Error::AotContainerRead(error.to_string())
        })?;
        let address_base: u64 = container_address_base(&file).ok_or_else(|| {
            crate::error::Error::AotContainerRead("container has no mapped address base".to_owned())
        })?;
        let address: u64 = address_base + u64::from(section.start_rva);
        for object_section in file.sections() {
            let Some((file_start, file_size)): Option<(u64, u64)> = object_section.file_range()
            else {
                continue;
            };
            let start: u64 = object_section.address();
            let end: u64 = start + file_size;
            if address < start || address >= end {
                continue;
            }
            return usize::try_from(file_start + (address - start)).map_err(
                |error: std::num::TryFromIntError| {
                    crate::error::Error::AotContainerRead(error.to_string())
                },
            );
        }
        Err(invalid(0, "test section is not file backed"))
    }

    fn fixture_attribution_state()
    -> crate::error::Result<(ReadyToRunHeader, Vec<AotType>, Vec<AotMethod>)> {
        let report: super::super::AotReport = super::super::detect(IMAGE);
        let header: ReadyToRunHeader = report
            .ready_to_run
            .ok_or_else(|| invalid(0, "test fixture has no NativeAOT header"))?;
        let mut metadata_header: ReadyToRunHeader = header.clone();
        metadata_header
            .sections
            .retain(|section: &AotSection| section.id != INVOKE_MAP_SECTION_ID);
        let attribution: super::super::AotMetadataAttribution =
            super::super::recover_metadata_attribution(IMAGE, &metadata_header)?;
        let mut methods: Vec<AotMethod> = attribution.methods;
        for method in &mut methods {
            method.entrypoint_rva = None;
        }
        Ok((header, attribution.types, methods))
    }

    fn fixture_state() -> crate::error::Result<(ReadyToRunHeader, Vec<AotMethod>)> {
        let (header, _types, methods): (ReadyToRunHeader, Vec<AotType>, Vec<AotMethod>) =
            fixture_attribution_state()?;
        Ok((header, methods))
    }

    fn real_mappings(header: &ReadyToRunHeader) -> crate::error::Result<Vec<(u32, u32)>> {
        let section: &AotSection = header
            .section(INVOKE_MAP_SECTION_ID)
            .ok_or_else(|| invalid(0, "test fixture has no invoke map"))?;
        let container: AotContainer<'_> = open_container(IMAGE)?;
        let bytes: &[u8] = container_section_bytes(IMAGE, &container, section, invalid)?;
        let offsets: Vec<usize> = entry_offsets(bytes)?;
        let mut mappings: Vec<(u32, u32)> = Vec::new();
        for offset in offsets {
            let mut cursor: usize = offset;
            let flags: u32 = decode_unsigned(bytes, &mut cursor)?;
            let method_reference: u32 = decode_unsigned(bytes, &mut cursor)?;
            let _declaring_type: u32 = decode_unsigned(bytes, &mut cursor)?;
            if flags & HAS_METADATA_HANDLE == 0 || flags & HAS_ENTRYPOINT == 0 {
                continue;
            }
            let entrypoint_index: u32 = decode_unsigned(bytes, &mut cursor)?;
            mappings.push((method_reference, entrypoint_index));
        }
        Ok(mappings)
    }

    fn attach_blob(
        header: &ReadyToRunHeader,
        methods: &mut [AotMethod],
        blob: &[u8],
    ) -> crate::error::Result<Vec<AotInvokeMapRefusal>> {
        let mut image: Vec<u8> = IMAGE.to_vec();
        let mut test_header: ReadyToRunHeader = header.clone();
        let section: &mut AotSection = test_header
            .sections
            .iter_mut()
            .find(|section: &&mut AotSection| section.id == INVOKE_MAP_SECTION_ID)
            .ok_or_else(|| invalid(0, "test fixture has no invoke map"))?;
        let file_offset: usize = section_file_offset(&image, section)?;
        let end: usize = file_offset + blob.len();
        image
            .get_mut(file_offset..end)
            .ok_or_else(|| invalid(0, "test invoke blob does not fit fixture"))?
            .copy_from_slice(blob);
        section.end_rva = section.start_rva
            + u32::try_from(blob.len())
                .map_err(|_: std::num::TryFromIntError| invalid(0, "test blob is too large"))?;
        attach_invoke_map(&image, &test_header, None, &[], methods)
            .map(|attachment: InvokeMapAttachment| attachment.refusals)
    }

    fn assert_invoke_error<T: std::fmt::Debug>(result: crate::error::Result<T>, needle: &str) {
        let error: crate::error::Error = result.expect_err("invoke map must be rejected");
        let rendered: String = error.to_string();
        assert!(rendered.contains("DR-DOTNET-0037"));
        assert!(rendered.contains(needle), "{rendered}");
    }

    fn method_at(methods: &[AotMethod], record_offset: u32) -> &AotMethod {
        methods
            .iter()
            .find(|method: &&AotMethod| method.record_offset == record_offset)
            .expect("test method record is recovered")
    }

    fn fixup_rva(header: &ReadyToRunHeader, index: u32) -> crate::error::Result<u32> {
        let section: &AotSection = header
            .section(COMMON_FIXUPS_SECTION_ID)
            .ok_or_else(|| invalid(0, "test fixture has no common fixups"))?;
        let container: AotContainer<'_> = open_container(IMAGE)?;
        let bytes: &[u8] = container_section_bytes(IMAGE, &container, section, invalid)?;
        resolve_fixup(
            bytes,
            container.address_base + u64::from(section.start_rva),
            container.address_base,
            &container.file,
            index,
        )
    }

    fn two_mappings(header: &ReadyToRunHeader) -> crate::error::Result<((u32, u32), (u32, u32))> {
        let mappings: Vec<(u32, u32)> = real_mappings(header)?;
        let first: (u32, u32) = *mappings
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?;
        let second: (u32, u32) = *mappings
            .iter()
            .find(|mapping: &&(u32, u32)| mapping.0 != first.0 && mapping.1 != first.1)
            .ok_or_else(|| invalid(0, "test fixture has no second mapped method"))?;
        Ok((first, second))
    }

    #[test]
    fn metadata_less_numeric_collision_does_not_attach_to_embedded_metadata()
    -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let mappings: Vec<(u32, u32)> = real_mappings(&header)?;
        let method_offset: u32 = methods
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no recovered methods"))?
            .record_offset;
        let entrypoint_index: u32 = mappings
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?
            .1;
        let blob: Vec<u8> = invoke_blob(&[TestEntry {
            flags: HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
            method_reference: method_offset,
            declaring_type_index: 0,
            entrypoint_index,
            tail: Vec::new(),
        }]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert!(refusals.is_empty());
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn identical_duplicate_mapping_is_recovered_once() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (mapping, _other): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        let entry: TestEntry = TestEntry::metadata(mapping.0, 0, mapping.1);
        let blob: Vec<u8> = invoke_blob(&[entry.clone(), entry]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert!(refusals.is_empty(), "{refusals:?}");
        let method: &AotMethod = method_at(&methods, mapping.0);
        assert_eq!(method.entrypoint_rva, Some(fixup_rva(&header, mapping.1)?));
        assert!(method.instantiation_entrypoint_rvas.is_empty());
        Ok(())
    }

    #[test]
    fn aliased_invoke_contexts_share_the_retained_word_quota() -> crate::error::Result<()> {
        let mut retained: usize = MAX_RETAINED_CONTEXT_WORDS - 3;
        let context: Vec<u32> = vec![IS_GENERIC_METHOD, 7, 9];
        retain_context_words(&mut retained, context.len(), 17)?;
        assert_eq!(retained, MAX_RETAINED_CONTEXT_WORDS);
        assert_invoke_error(
            retain_context_words(&mut retained, context.len(), 17),
            "retained context quota",
        );
        assert_eq!(retained, MAX_RETAINED_CONTEXT_WORDS);
        assert_invoke_error(
            retain_context_words(&mut retained, usize::MAX, 17),
            "retained context quota",
        );
        Ok(())
    }

    #[test]
    fn aliased_refusals_charge_names_and_reasons_before_retaining_text() -> crate::error::Result<()>
    {
        let (_header, methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let method: &AotMethod = methods
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no methods"))?;
        let make_refusal = || EntryRefusal {
            entry_offset: 17,
            method_index: Some(0),
            error: invalid(17, "invalid aliased entry"),
        };
        let charge: usize = method.name.len() + make_refusal().error.to_string().len();
        let mut retained: usize = MAX_REFUSAL_TEXT_BYTES - charge;
        let record: AotInvokeMapRefusal = refusal_record(&methods, make_refusal(), &mut retained)?;
        assert_eq!(record.method_name.as_deref(), Some(method.name.as_str()));
        assert_eq!(retained, MAX_REFUSAL_TEXT_BYTES);
        assert_invoke_error(
            refusal_record(&methods, make_refusal(), &mut retained),
            "refusal text quota",
        );
        assert_eq!(retained, MAX_REFUSAL_TEXT_BYTES);
        Ok(())
    }

    #[test]
    fn repeated_long_method_names_refuse_the_map_before_unbounded_cloning()
    -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (first, second): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        let method: &mut AotMethod = methods
            .iter_mut()
            .find(|method: &&mut AotMethod| method.record_offset == first.0)
            .ok_or_else(|| invalid(0, "test mapped method is missing"))?;
        method.name = "x".repeat(MAX_REFUSAL_TEXT_BYTES / 2);
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::metadata(first.0, 0, first.1),
            TestEntry::metadata(first.0, 0, second.1),
        ]);
        assert_invoke_error(
            attach_blob(&header, &mut methods, &blob),
            "refusal text quota",
        );
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn conflicting_mapping_is_refused_by_name_and_the_rest_of_the_map_survives()
    -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (first, second): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::metadata(first.0, 0, first.1),
            TestEntry::metadata(first.0, 0, second.1),
            TestEntry::metadata(second.0, 0, second.1),
        ]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        let conflicted_name: String = method_at(&methods, first.0).name.clone();
        assert_eq!(refusals.len(), 2, "{refusals:?}");
        for refusal in &refusals {
            assert_eq!(refusal.method_record_offset, Some(first.0));
            assert_eq!(
                refusal.method_name.as_deref(),
                Some(conflicted_name.as_str())
            );
            assert!(
                refusal.reason.contains("DR-DOTNET-0037"),
                "{}",
                refusal.reason
            );
            assert!(
                refusal.reason.contains("different entrypoints"),
                "{}",
                refusal.reason
            );
        }
        assert_eq!(method_at(&methods, first.0).entrypoint_rva, None);
        assert_eq!(
            method_at(&methods, second.0).entrypoint_rva,
            Some(fixup_rva(&header, second.1)?)
        );
        Ok(())
    }

    #[test]
    fn unmatched_metadata_mapping_is_refused_alone() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (mapping, _other): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        let unmatched: u32 = (0..u32::MAX)
            .find(|candidate: &u32| {
                methods
                    .iter()
                    .all(|method: &AotMethod| method.record_offset != *candidate)
            })
            .ok_or_else(|| invalid(0, "test fixture covers every method offset"))?;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::metadata(mapping.0, 0, mapping.1),
            TestEntry::metadata(unmatched, 0, mapping.1),
        ]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        let refusal: &AotInvokeMapRefusal = &refusals[0];
        assert_eq!(refusal.method_record_offset, None);
        assert!(
            refusal.reason.contains("no recovered method"),
            "{}",
            refusal.reason
        );
        assert_eq!(
            method_at(&methods, mapping.0).entrypoint_rva,
            Some(fixup_rva(&header, mapping.1)?)
        );
        Ok(())
    }

    #[test]
    fn distinct_declaring_types_keep_every_entrypoint() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (first, second): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::metadata(first.0, 1, first.1),
            TestEntry::metadata(first.0, 2, second.1),
        ]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert!(refusals.is_empty(), "{refusals:?}");
        let method: &AotMethod = method_at(&methods, first.0);
        assert_eq!(method.entrypoint_rva, None);
        let mut expected: Vec<u32> =
            vec![fixup_rva(&header, first.1)?, fixup_rva(&header, second.1)?];
        expected.sort_unstable();
        assert_eq!(method.instantiation_entrypoint_rvas, expected);
        Ok(())
    }

    #[test]
    fn generic_instantiations_are_keyed_by_every_type_argument() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (first, second): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        for method in &mut methods {
            if method.record_offset == first.0 {
                method
                    .signature
                    .as_mut()
                    .expect("test method has a signature")
                    .generic_parameter_count = 2;
            }
        }
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::generic(first.0, first.1, 2, &[7, 9]),
            TestEntry::generic(first.0, second.1, 2, &[7, 11]),
        ]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert!(refusals.is_empty(), "{refusals:?}");
        let method: &AotMethod = method_at(&methods, first.0);
        let mut expected: Vec<u32> =
            vec![fixup_rva(&header, first.1)?, fixup_rva(&header, second.1)?];
        expected.sort_unstable();
        assert_eq!(method.instantiation_entrypoint_rvas, expected);
        Ok(())
    }

    #[test]
    fn generic_argument_count_that_contradicts_the_signature_is_refused() -> crate::error::Result<()>
    {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let (first, second): ((u32, u32), (u32, u32)) = two_mappings(&header)?;
        for method in &mut methods {
            if method.record_offset == first.0 {
                method
                    .signature
                    .as_mut()
                    .expect("test method has a signature")
                    .generic_parameter_count = 1;
            }
        }
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry::generic(first.0, first.1, 2, &[7, 9]),
            TestEntry::metadata(second.0, 0, second.1),
        ]);
        let refusals: Vec<AotInvokeMapRefusal> = attach_blob(&header, &mut methods, &blob)?;
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert!(
            refusals[0]
                .reason
                .contains("differs from the method signature"),
            "{}",
            refusals[0].reason
        );
        assert_eq!(refusals[0].method_record_offset, Some(first.0));
        assert_eq!(method_at(&methods, first.0).entrypoint_rva, None);
        assert_eq!(
            method_at(&methods, second.0).entrypoint_rva,
            Some(fixup_rva(&header, second.1)?)
        );
        Ok(())
    }

    #[test]
    fn malformed_hashtable_framing_still_refuses_the_map() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        assert_invoke_error(
            attach_blob(&header, &mut methods, &[u8::MAX]),
            "bucket count",
        );
        Ok(())
    }

    fn generic_net10_image() -> Vec<u8> {
        disrobe_testkit::load_fixture(
            "corpus/dotnet/aot/aot_maps_net10_x86_64/aot_maps_net10_x86_64.exe",
            4 * 1024 * 1024,
        )
        .unwrap_or_else(|error| panic!("the .NET 10 NativeAOT maps fixture is missing: {error}"))
    }

    #[test]
    fn generic_instantiations_over_value_and_reference_types_keep_the_attribution() {
        let image: Vec<u8> = generic_net10_image();
        let report: super::super::AotReport = super::super::detect(&image);
        assert_eq!(
            report.metadata_attribution.status,
            super::super::AotMetadataStatus::Recovered
        );
        assert_eq!(report.invoke_map_refusals.len(), 19);
        assert!(report.invoke_map_refusals.iter().all(|refusal| {
            refusal
                .reason
                .contains("invoke-map method does not have exactly one metadata owner")
        }));
        let readings: &super::super::AotType = report
            .metadata_attribution
            .types
            .iter()
            .find(|candidate: &&super::super::AotType| candidate.name == "Readings")
            .expect("Readings is attributed");
        let method = |name: &str| -> &AotMethod {
            report
                .metadata_attribution
                .methods
                .iter()
                .find(|method: &&AotMethod| {
                    method.name == name
                        && readings
                            .method_record_offsets
                            .contains(&method.record_offset)
                })
                .unwrap_or_else(|| panic!("Readings.{name} is attributed"))
        };
        assert!(method("Add").entrypoint_rva.is_some());
        assert_eq!(method("Echo").entrypoint_rva, None);
        assert_eq!(method("Echo").instantiation_entrypoint_rvas.len(), 3);
        assert_eq!(method("Relabel").entrypoint_rva, None);
        assert_eq!(method("Relabel").instantiation_entrypoint_rvas.len(), 3);
    }

    #[test]
    fn duplicate_metadata_owner_refuses_only_type_attribution() -> crate::error::Result<()> {
        let (header, mut types, mut methods): (ReadyToRunHeader, Vec<AotType>, Vec<AotMethod>) =
            fixture_attribution_state()?;
        let mappings: Vec<(u32, u32)> = real_mappings(&header)?;
        let method_offset: u32 = mappings
            .iter()
            .map(|(method_offset, _entrypoint_index): &(u32, u32)| *method_offset)
            .find(|method_offset: &u32| {
                types
                    .iter()
                    .filter(|candidate: &&AotType| {
                        candidate.method_record_offsets.contains(method_offset)
                    })
                    .count()
                    == 1
            })
            .ok_or_else(|| invalid(0, "test fixture has no uniquely owned mapped method"))?;
        let mut duplicate: AotType = types
            .iter()
            .find(|candidate: &&AotType| candidate.method_record_offsets.contains(&method_offset))
            .ok_or_else(|| invalid(0, "test method owner is missing"))?
            .clone();
        duplicate.record_offset = u32::MAX;
        duplicate.method_record_offsets = vec![method_offset];
        types.push(duplicate);
        let refusals: Vec<AotInvokeMapRefusal> =
            attach_invoke_map(IMAGE, &header, Some(&types), &[], &mut methods)?.refusals;
        assert!(refusals.iter().any(|refusal: &AotInvokeMapRefusal| {
            refusal.method_record_offset == Some(method_offset)
                && refusal
                    .reason
                    .contains("invoke-map method does not have exactly one metadata owner")
        }));
        assert!(method_at(&methods, method_offset).entrypoint_rva.is_some());
        Ok(())
    }

    #[test]
    fn executable_fixup_is_not_a_runtime_type() -> crate::error::Result<()> {
        let (header, _methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let entrypoint_index: u32 = real_mappings(&header)?
            .first()
            .map(|(_method_offset, entrypoint_index): &(u32, u32)| *entrypoint_index)
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?;
        let section: &AotSection = header
            .section(COMMON_FIXUPS_SECTION_ID)
            .ok_or_else(|| invalid(0, "test fixture has no common fixups"))?;
        let container: AotContainer<'_> = open_container(IMAGE)?;
        let bytes: &[u8] = container_section_bytes(IMAGE, &container, section, invalid)?;
        assert_invoke_error(
            resolve_runtime_type_fixup(
                bytes,
                container.address_base + u64::from(section.start_rva),
                container.address_base,
                &container.file,
                entrypoint_index,
                invalid,
            ),
            "non-executable storage",
        );
        Ok(())
    }

    #[test]
    fn virtual_executable_tail_is_not_a_file_backed_entrypoint() -> crate::error::Result<()> {
        let mut image: Vec<u8> = IMAGE.to_vec();
        let pe_offset: usize = usize::try_from(read_u32_le_at(&image, 0x3c).map_err(
            |_: disrobe_bytes::ByteReadError| invalid(0x3c, "test PE header is truncated"),
        )?)
        .map_err(|_: std::num::TryFromIntError| {
            invalid(0x3c, "test PE offset does not fit usize")
        })?;
        let coff_offset: usize = pe_offset + 4;
        let optional_size: usize = usize::from(read_u16_le_at(&image, coff_offset + 16).map_err(
            |_: disrobe_bytes::ByteReadError| invalid(coff_offset, "test COFF header is truncated"),
        )?);
        let text_header: usize = coff_offset + 20 + optional_size;
        let raw_size: u32 = read_u32_le_at(&image, text_header + 16).map_err(
            |_: disrobe_bytes::ByteReadError| {
                invalid(text_header, "test section header is truncated")
            },
        )?;
        let virtual_size: u32 = raw_size
            .checked_add(1)
            .ok_or_else(|| invalid(text_header, "test virtual size overflowed"))?;
        image[text_header + 8..text_header + 12].copy_from_slice(&virtual_size.to_le_bytes());
        let file: ObjFile<'_, &[u8]> =
            ObjFile::parse(image.as_slice()).map_err(|error: object::Error| {
                crate::error::Error::AotContainerRead(error.to_string())
            })?;
        let text: object::Section<'_, '_, &[u8]> = file
            .sections()
            .find(|section: &object::Section<'_, '_, &[u8]>| section.kind() == SectionKind::Text)
            .ok_or_else(|| invalid(0, "test image has no executable section"))?;
        let (_file_offset, file_size): (u64, u64) = text
            .file_range()
            .ok_or_else(|| invalid(0, "test executable section is not file backed"))?;
        assert!(text.size() > file_size);
        let target: u64 = text.address() + file_size;
        let address_base: u64 = container_address_base(&file)
            .ok_or_else(|| invalid(0, "test image has no address base"))?;
        assert_invoke_error(
            resolve_fixup(&[0, 0, 0, 0], target, address_base, &file, 0),
            "executable code",
        );
        Ok(())
    }
}
