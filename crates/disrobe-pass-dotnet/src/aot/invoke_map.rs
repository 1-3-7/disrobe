use disrobe_binfmt::{Endian, NativeFile, parse_native};
use disrobe_bytes::{read_i32_le_at, read_u16_le_at, read_u32_le_at};
use object::read::File as ObjFile;
use object::{Object as _, ObjectSection as _, SectionKind};

use super::metadata_records::AotMethod;
use super::{
    AotSection, ReadyToRunHeader, address_range_is_inside, container_address_base,
    decode_metadata_unsigned, section_bytes_for_address, section_views_agree,
    supported_native_format,
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
const MAX_INVOKE_MAP_BUCKETS: usize = 65_536;
const MAX_INVOKE_MAP_ENTRIES: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeMapLayout {
    FlaggedMetadataOrName,
    EmbeddedMetadataOnly,
}

impl InvokeMapLayout {
    const fn for_header(header: &ReadyToRunHeader) -> Self {
        if header.major_version == 16 && header.minor_version == 0 {
            Self::EmbeddedMetadataOnly
        } else {
            Self::FlaggedMetadataOrName
        }
    }

    const fn allowed_flags(self) -> u32 {
        match self {
            Self::FlaggedMetadataOrName => INVOKE_FLAGS_MASK,
            Self::EmbeddedMetadataOnly => {
                INVOKE_FLAGS_MASK & !(HAS_METADATA_HANDLE | IS_UNIVERSAL_CANONICAL_ENTRY)
            }
        }
    }

    const fn has_metadata_offset(self, flags: u32) -> bool {
        match self {
            Self::FlaggedMetadataOrName => flags & HAS_METADATA_HANDLE != 0,
            Self::EmbeddedMetadataOnly => true,
        }
    }

    const fn is_universal_canonical(self, flags: u32) -> bool {
        matches!(self, Self::FlaggedMetadataOrName) && flags & IS_UNIVERSAL_CANONICAL_ENTRY != 0
    }

    const fn has_generic_signature_reference(self, flags: u32) -> bool {
        matches!(self, Self::FlaggedMetadataOrName) && flags & REQUIRES_INST_ARG != 0
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct InvokeIdentity {
    method_offset: u32,
    declaring_type_index: u32,
    generic_context: Vec<u32>,
}

#[derive(Debug)]
struct InvokeMapping {
    identity: InvokeIdentity,
    method_index: usize,
    entrypoint_rva: Option<u32>,
}

fn invalid(at: usize, reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidAotInvokeMap {
        offset: u32::try_from(at).map_or(u32::MAX, |value: u32| value),
        reason,
    }
}

fn unique_section(header: &ReadyToRunHeader, id: i32) -> crate::error::Result<Option<&AotSection>> {
    let mut found: Option<&AotSection> = None;
    for section in &header.sections {
        if section.id != id {
            continue;
        }
        if found.is_some() {
            return Err(invalid(
                0,
                "invoke-map dependency section appears more than once",
            ));
        }
        found = Some(section);
    }
    Ok(found)
}

fn section_bytes<'a>(
    image: &'a [u8],
    file: &ObjFile<'a, &'a [u8]>,
    address_base: u64,
    section: &AotSection,
) -> crate::error::Result<&'a [u8]> {
    let start: u64 = address_base
        .checked_add(u64::from(section.start_rva))
        .ok_or_else(|| invalid(0, "invoke-map section start address overflowed"))?;
    let end: u64 = address_base
        .checked_add(u64::from(section.end_rva))
        .ok_or_else(|| invalid(0, "invoke-map section end address overflowed"))?;
    section_bytes_for_address(image, file, start, end).ok_or_else(|| {
        invalid(
            0,
            "invoke-map dependency section is not entirely file backed",
        )
    })
}

fn decode_signed(bytes: &[u8], at: usize) -> crate::error::Result<(i32, usize)> {
    let first: u8 = *bytes
        .get(at)
        .ok_or_else(|| invalid(at, "signed integer is truncated"))?;
    if first & 1 == 0 {
        return Ok((i32::from(first as i8) >> 1, 1));
    }
    if first & 3 == 1 {
        let second: i32 = i32::from(
            *bytes
                .get(
                    at.checked_add(1)
                        .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?,
                )
                .ok_or_else(|| invalid(at, "signed integer is truncated"))? as i8,
        );
        return Ok((i32::from(first >> 2) | (second << 6), 2));
    }
    if first & 7 == 3 {
        let second: i32 = i32::from(
            *bytes
                .get(
                    at.checked_add(1)
                        .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?,
                )
                .ok_or_else(|| invalid(at, "signed integer is truncated"))?,
        );
        let third: i32 = i32::from(
            *bytes
                .get(
                    at.checked_add(2)
                        .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?,
                )
                .ok_or_else(|| invalid(at, "signed integer is truncated"))? as i8,
        );
        return Ok((i32::from(first >> 3) | (second << 5) | (third << 13), 3));
    }
    if first & 15 == 7 {
        let second_at: usize = at
            .checked_add(1)
            .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?;
        let third_at: usize = at
            .checked_add(2)
            .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?;
        let fourth_at: usize = at
            .checked_add(3)
            .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?;
        let second: i32 = i32::from(
            *bytes
                .get(second_at)
                .ok_or_else(|| invalid(at, "signed integer is truncated"))?,
        );
        let third: i32 = i32::from(
            *bytes
                .get(third_at)
                .ok_or_else(|| invalid(at, "signed integer is truncated"))?,
        );
        let fourth: i32 = i32::from(
            *bytes
                .get(fourth_at)
                .ok_or_else(|| invalid(at, "signed integer is truncated"))? as i8,
        );
        return Ok((
            i32::from(first >> 4) | (second << 4) | (third << 12) | (fourth << 20),
            4,
        ));
    }
    if first & 31 == 15 {
        let value: i32 = read_i32_le_at(
            bytes,
            at.checked_add(1)
                .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?,
        )
        .map_err(|_: disrobe_bytes::ByteReadError| invalid(at, "signed integer is truncated"))?;
        return Ok((value, 5));
    }
    Err(invalid(at, "signed integer prefix is unsupported"))
}

fn decode_unsigned(bytes: &[u8], at: &mut usize) -> crate::error::Result<u32> {
    let (value, width): (u32, usize) = decode_metadata_unsigned(bytes, *at)
        .ok_or_else(|| invalid(*at, "unsigned integer is malformed"))?;
    *at = at
        .checked_add(width)
        .ok_or_else(|| invalid(*at, "unsigned integer cursor overflowed"))?;
    Ok(value)
}

fn read_bucket_index(bytes: &[u8], at: usize, width: usize) -> crate::error::Result<usize> {
    let value: u32 = match width {
        1 => u32::from(
            *bytes
                .get(at)
                .ok_or_else(|| invalid(at, "bucket index is truncated"))?,
        ),
        2 => u32::from(
            read_u16_le_at(bytes, at).map_err(|_: disrobe_bytes::ByteReadError| {
                invalid(at, "bucket index is truncated")
            })?,
        ),
        4 => read_u32_le_at(bytes, at)
            .map_err(|_: disrobe_bytes::ByteReadError| invalid(at, "bucket index is truncated"))?,
        _ => return Err(invalid(at, "bucket index width is unsupported")),
    };
    usize::try_from(value)
        .map_err(|_: std::num::TryFromIntError| invalid(at, "bucket index does not fit usize"))
}

fn entry_offsets(bytes: &[u8]) -> crate::error::Result<Vec<usize>> {
    if bytes.len() > MAX_INVOKE_MAP_BYTES {
        return Err(invalid(0, "invoke-map blob exceeds parser byte limit"));
    }
    let header: u8 = *bytes
        .first()
        .ok_or_else(|| invalid(0, "invoke map is empty"))?;
    let shift: u32 = u32::from(header >> 2);
    let bucket_count: usize = 1usize
        .checked_shl(shift)
        .ok_or_else(|| invalid(0, "invoke-map bucket count overflowed"))?;
    if bucket_count > MAX_INVOKE_MAP_BUCKETS {
        return Err(invalid(0, "invoke-map bucket count exceeds parser limit"));
    }
    let width: usize = 1usize
        .checked_shl(u32::from(header & 3))
        .ok_or_else(|| invalid(0, "invoke-map bucket index width overflowed"))?;
    if width > 4 {
        return Err(invalid(0, "invoke-map bucket index width is unsupported"));
    }
    let index_count: usize = bucket_count
        .checked_add(1)
        .ok_or_else(|| invalid(0, "invoke-map bucket index count overflowed"))?;
    let table_bytes: usize = index_count
        .checked_mul(width)
        .ok_or_else(|| invalid(0, "invoke-map bucket table size overflowed"))?;
    let entry_floor: usize = 1usize
        .checked_add(table_bytes)
        .ok_or_else(|| invalid(0, "invoke-map bucket table end overflowed"))?;
    if entry_floor > bytes.len() {
        return Err(invalid(0, "invoke-map bucket table is truncated"));
    }
    let capacity: usize = bytes
        .len()
        .saturating_sub(entry_floor)
        .min(MAX_INVOKE_MAP_ENTRIES);
    let mut offsets: Vec<usize> = Vec::new();
    offsets
        .try_reserve_exact(capacity)
        .map_err(|_| invalid(0, "invoke-map entry allocation failed"))?;
    for bucket in 0..bucket_count {
        let start_at: usize = 1usize
            .checked_add(
                bucket
                    .checked_mul(width)
                    .ok_or_else(|| invalid(0, "invoke-map bucket offset overflowed"))?,
            )
            .ok_or_else(|| invalid(0, "invoke-map bucket offset overflowed"))?;
        let end_at: usize = start_at
            .checked_add(width)
            .ok_or_else(|| invalid(start_at, "invoke-map bucket end offset overflowed"))?;
        let start: usize = 1usize
            .checked_add(read_bucket_index(bytes, start_at, width)?)
            .ok_or_else(|| invalid(start_at, "invoke-map bucket start overflowed"))?;
        let end: usize = 1usize
            .checked_add(read_bucket_index(bytes, end_at, width)?)
            .ok_or_else(|| invalid(end_at, "invoke-map bucket end overflowed"))?;
        if start < entry_floor || end < start || end > bytes.len() {
            return Err(invalid(start_at, "invoke-map bucket range is invalid"));
        }
        let mut cursor: usize = start;
        while cursor < end {
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| invalid(cursor, "invoke-map hash cursor overflowed"))?;
            let relative_at: usize = cursor;
            let (delta, width): (i32, usize) = decode_signed(bytes, relative_at)?;
            cursor = cursor
                .checked_add(width)
                .ok_or_else(|| invalid(relative_at, "invoke-map entry cursor overflowed"))?;
            if cursor > end {
                return Err(invalid(
                    relative_at,
                    "invoke-map bucket entry exceeds its range",
                ));
            }
            let target: usize = if delta >= 0 {
                relative_at.checked_add(delta as usize)
            } else {
                relative_at.checked_sub(delta.unsigned_abs() as usize)
            }
            .ok_or_else(|| invalid(relative_at, "invoke-map entry target overflowed"))?;
            if target < entry_floor || target >= bytes.len() {
                return Err(invalid(
                    relative_at,
                    "invoke-map entry target is outside the blob",
                ));
            }
            offsets.push(target);
            if offsets.len() > MAX_INVOKE_MAP_ENTRIES {
                return Err(invalid(
                    relative_at,
                    "invoke-map entry count exceeds parser limit",
                ));
            }
        }
    }
    Ok(offsets)
}

fn resolve_fixup<'a>(
    bytes: &[u8],
    section_start: u64,
    address_base: u64,
    file: &ObjFile<'a, &'a [u8]>,
    index: u32,
) -> crate::error::Result<u32> {
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
    let rva: u64 = target.checked_sub(address_base).ok_or_else(|| {
        invalid(
            slot_delta,
            "common-fixup entrypoint precedes the image base",
        )
    })?;
    u32::try_from(rva).map_err(|_: std::num::TryFromIntError| {
        invalid(slot_delta, "entrypoint RVA does not fit u32")
    })
}

pub(super) fn attach_invoke_map_entrypoints(
    image: &[u8],
    header: &ReadyToRunHeader,
    methods: &mut [AotMethod],
) -> crate::error::Result<()> {
    let layout: InvokeMapLayout = InvokeMapLayout::for_header(header);
    let Some(invoke_section): Option<&AotSection> = unique_section(header, INVOKE_MAP_SECTION_ID)?
    else {
        return Ok(());
    };
    let fixups_section: &AotSection = unique_section(header, COMMON_FIXUPS_SECTION_ID)?
        .ok_or_else(|| invalid(0, "invoke map has no common-fixups section"))?;
    let native: NativeFile = parse_native(image).map_err(|error: disrobe_binfmt::Error| {
        crate::error::Error::AotContainerRead(error.to_string())
    })?;
    if !supported_native_format(native.format) || !matches!(native.endian, Endian::Little) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            native.format.label(),
        ));
    }
    let file: ObjFile<'_, &[u8]> = ObjFile::parse(image)
        .map_err(|error: object::Error| crate::error::Error::AotContainerRead(error.to_string()))?;
    if !section_views_agree(&native, &file) {
        return Err(crate::error::Error::AotContainerRead(
            "container parsers disagree on section layout".to_owned(),
        ));
    }
    let address_base: u64 = container_address_base(&file).ok_or_else(|| {
        crate::error::Error::AotContainerRead("container has no mapped address base".to_owned())
    })?;
    let invoke_bytes: &[u8] = section_bytes(image, &file, address_base, invoke_section)?;
    let fixups_bytes: &[u8] = section_bytes(image, &file, address_base, fixups_section)?;
    if fixups_bytes.len() > MAX_INVOKE_MAP_BYTES {
        return Err(invalid(0, "common-fixups blob exceeds parser byte limit"));
    }
    if !fixups_bytes.len().is_multiple_of(4) {
        return Err(invalid(
            0,
            "common-fixups blob has a partial relative pointer",
        ));
    }
    let fixups_start: u64 = address_base
        .checked_add(u64::from(fixups_section.start_rva))
        .ok_or_else(|| invalid(0, "common-fixups section start address overflowed"))?;
    let mut method_indices: Vec<(u32, usize)> = Vec::new();
    method_indices
        .try_reserve_exact(methods.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for (index, method) in methods.iter().enumerate() {
        method_indices.push((method.record_offset, index));
    }
    method_indices.sort_unstable();
    let offsets: Vec<usize> = entry_offsets(invoke_bytes)?;
    let mut recovered: Vec<InvokeMapping> = Vec::new();
    recovered
        .try_reserve_exact(offsets.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for offset in offsets {
        let mut cursor: usize = offset;
        let flags: u32 = decode_unsigned(invoke_bytes, &mut cursor)?;
        if flags & !layout.allowed_flags() != 0 {
            return Err(invalid(offset, "invoke-map entry uses unsupported flags"));
        }
        let method_offset: u32 = decode_unsigned(invoke_bytes, &mut cursor)?;
        let declaring_type_index: u32 = decode_unsigned(invoke_bytes, &mut cursor)?;
        let entrypoint_index: Option<u32> = if flags & HAS_ENTRYPOINT == 0 {
            None
        } else {
            Some(decode_unsigned(invoke_bytes, &mut cursor)?)
        };
        if !layout.has_metadata_offset(flags) {
            continue;
        }
        let position: usize = method_indices
            .binary_search_by_key(&method_offset, |(method_offset, _index): &(u32, usize)| {
                *method_offset
            })
            .map_err(|_: usize| {
                invalid(
                    0,
                    "invoke-map metadata handle has no recovered method record",
                )
            })?;
        let method_index: usize = method_indices[position].1;
        let method: &AotMethod = methods
            .get(method_index)
            .ok_or_else(|| invalid(0, "invoke-map method index is outside recovered methods"))?;
        if flags & NEEDS_PARAMETER_INTERPRETATION == 0 {
            let _invoke_stub_index: u32 = decode_unsigned(invoke_bytes, &mut cursor)?;
        }
        let is_universal_canonical: bool = layout.is_universal_canonical(flags);
        let generic_flags: u32 = flags
            & (IS_GENERIC_METHOD
                | REQUIRES_INST_ARG
                | if is_universal_canonical {
                    IS_UNIVERSAL_CANONICAL_ENTRY
                } else {
                    0
                });
        let generic_count: usize = if flags & IS_GENERIC_METHOD != 0 && !is_universal_canonical {
            usize::try_from(
                method
                    .signature
                    .as_ref()
                    .ok_or_else(|| invalid(offset, "generic invoke-map method has no signature"))?
                    .generic_parameter_count,
            )
            .map_err(|_: std::num::TryFromIntError| {
                invalid(offset, "generic invoke-map arity does not fit usize")
            })?
        } else {
            0
        };
        let generic_capacity: usize = generic_count
            .checked_add(2)
            .ok_or_else(|| invalid(offset, "generic invoke-map allocation size overflowed"))?;
        let mut generic_context: Vec<u32> = Vec::new();
        generic_context
            .try_reserve_exact(generic_capacity)
            .map_err(|_| invalid(offset, "generic invoke-map allocation failed"))?;
        generic_context.push(generic_flags);
        if flags & IS_GENERIC_METHOD != 0 {
            if layout.has_generic_signature_reference(flags) {
                generic_context.push(decode_unsigned(invoke_bytes, &mut cursor)?);
            }
            if !is_universal_canonical {
                for _ in 0..generic_count {
                    generic_context.push(decode_unsigned(invoke_bytes, &mut cursor)?);
                }
            }
        }
        let entrypoint_rva: Option<u32> = entrypoint_index
            .map(|index: u32| resolve_fixup(fixups_bytes, fixups_start, address_base, &file, index))
            .transpose()?;
        recovered.push(InvokeMapping {
            identity: InvokeIdentity {
                method_offset,
                declaring_type_index,
                generic_context,
            },
            method_index,
            entrypoint_rva,
        });
    }
    recovered.sort_unstable_by(|left: &InvokeMapping, right: &InvokeMapping| {
        left.identity.cmp(&right.identity)
    });
    if recovered.windows(2).any(
        |pair: &[InvokeMapping]| matches!(pair, [left, right] if left.identity == right.identity),
    ) {
        return Err(invalid(
            0,
            "invoke map has a duplicate embedded-metadata method mapping",
        ));
    }
    let mut entrypoints: Vec<(usize, u32)> = Vec::new();
    entrypoints
        .try_reserve_exact(recovered.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for mapping in recovered {
        if let Some(entrypoint_rva) = mapping.entrypoint_rva {
            entrypoints.push((mapping.method_index, entrypoint_rva));
        }
    }
    entrypoints.sort_unstable();
    let mut assignments: Vec<(usize, u32)> = Vec::new();
    assignments
        .try_reserve_exact(entrypoints.len())
        .map_err(|_| invalid(0, "invoke-map result allocation failed"))?;
    for group in entrypoints.chunk_by(|left: &(usize, u32), right: &(usize, u32)| left.0 == right.0)
    {
        let Some((method_index, entrypoint_rva)): Option<&(usize, u32)> = group.first() else {
            continue;
        };
        if group
            .iter()
            .all(|(_index, candidate): &(usize, u32)| candidate == entrypoint_rva)
        {
            assignments.push((*method_index, *entrypoint_rva));
        }
    }
    for (method_index, entrypoint_rva) in assignments {
        methods
            .get_mut(method_index)
            .ok_or_else(|| invalid(0, "invoke-map method index is outside recovered methods"))?
            .entrypoint_rva = Some(entrypoint_rva);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use object::{Object as _, ObjectSection as _};

    use super::*;

    const IMAGE: &[u8] =
        include_bytes!("../../tests/fixtures/native_aot/invoke_map_net9_x86_64.exe");
    #[derive(Clone, Copy)]
    struct TestEntry {
        flags: u32,
        method_reference: u32,
        declaring_type_index: u32,
        entrypoint_index: u32,
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

    fn fixture_state() -> crate::error::Result<(ReadyToRunHeader, Vec<AotMethod>)> {
        let report: super::super::AotReport = super::super::detect(IMAGE);
        let header: ReadyToRunHeader = report
            .ready_to_run
            .ok_or_else(|| invalid(0, "test fixture has no NativeAOT header"))?;
        let mut metadata_header: ReadyToRunHeader = header.clone();
        metadata_header
            .sections
            .retain(|section: &AotSection| section.id != INVOKE_MAP_SECTION_ID);
        let mut methods: Vec<AotMethod> =
            super::super::recover_metadata_attribution(IMAGE, &metadata_header)?.methods;
        for method in &mut methods {
            method.entrypoint_rva = None;
        }
        Ok((header, methods))
    }

    fn real_mappings(header: &ReadyToRunHeader) -> crate::error::Result<Vec<(u32, u32)>> {
        let file: ObjFile<'_, &[u8]> = ObjFile::parse(IMAGE).map_err(|error: object::Error| {
            crate::error::Error::AotContainerRead(error.to_string())
        })?;
        let address_base: u64 = container_address_base(&file).ok_or_else(|| {
            crate::error::Error::AotContainerRead("container has no mapped address base".to_owned())
        })?;
        let section: &AotSection = header
            .section(INVOKE_MAP_SECTION_ID)
            .ok_or_else(|| invalid(0, "test fixture has no invoke map"))?;
        let bytes: &[u8] = section_bytes(IMAGE, &file, address_base, section)?;
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
    ) -> crate::error::Result<()> {
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
        attach_invoke_map_entrypoints(&image, &test_header, methods)
    }

    fn assert_invoke_error(result: crate::error::Result<()>, needle: &str) {
        let error: crate::error::Error = result.expect_err("invoke map must be rejected");
        let rendered: String = error.to_string();
        assert!(rendered.contains("DR-DOTNET-0037"));
        assert!(rendered.contains(needle), "{rendered}");
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
        }]);
        attach_blob(&header, &mut methods, &blob)?;
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn duplicate_metadata_mapping_is_rejected() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let mapping: (u32, u32) = *real_mappings(&header)?
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?;
        let entry: TestEntry = TestEntry {
            flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
            method_reference: mapping.0,
            declaring_type_index: 0,
            entrypoint_index: mapping.1,
        };
        let blob: Vec<u8> = invoke_blob(&[entry, entry]);
        assert_invoke_error(attach_blob(&header, &mut methods, &blob), "duplicate");
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn conflicting_metadata_mapping_is_rejected() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let mappings: Vec<(u32, u32)> = real_mappings(&header)?;
        let first: (u32, u32) = *mappings
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?;
        let second_index: u32 = mappings
            .iter()
            .find(|mapping: &&(u32, u32)| mapping.1 != first.1)
            .ok_or_else(|| invalid(0, "test fixture has no distinct mapped entrypoints"))?
            .1;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: first.0,
                declaring_type_index: 0,
                entrypoint_index: first.1,
            },
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: first.0,
                declaring_type_index: 0,
                entrypoint_index: second_index,
            },
        ]);
        assert_invoke_error(attach_blob(&header, &mut methods, &blob), "duplicate");
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn unmatched_metadata_mapping_is_rejected() -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let mappings: Vec<(u32, u32)> = real_mappings(&header)?;
        let unmatched: u32 = (0..u32::MAX)
            .find(|candidate: &u32| {
                methods
                    .iter()
                    .all(|method: &AotMethod| method.record_offset != *candidate)
            })
            .ok_or_else(|| invalid(0, "test fixture covers every method offset"))?;
        let entrypoint_index: u32 = mappings
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?
            .1;
        let matched: u32 = methods
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no recovered methods"))?
            .record_offset;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: matched,
                declaring_type_index: 0,
                entrypoint_index,
            },
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: unmatched,
                declaring_type_index: 0,
                entrypoint_index,
            },
        ]);
        assert_invoke_error(
            attach_blob(&header, &mut methods, &blob),
            "no recovered method",
        );
        assert!(
            methods
                .iter()
                .all(|method: &AotMethod| method.entrypoint_rva.is_none())
        );
        Ok(())
    }

    #[test]
    fn distinct_declaring_types_with_distinct_entrypoints_are_valid_and_ambiguous()
    -> crate::error::Result<()> {
        let (header, mut methods): (ReadyToRunHeader, Vec<AotMethod>) = fixture_state()?;
        let mappings: Vec<(u32, u32)> = real_mappings(&header)?;
        let first: (u32, u32) = *mappings
            .first()
            .ok_or_else(|| invalid(0, "test fixture has no mapped entrypoints"))?;
        let second_index: u32 = mappings
            .iter()
            .find(|mapping: &&(u32, u32)| mapping.1 != first.1)
            .ok_or_else(|| invalid(0, "test fixture has no distinct mapped entrypoints"))?
            .1;
        let blob: Vec<u8> = invoke_blob(&[
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: first.0,
                declaring_type_index: 1,
                entrypoint_index: first.1,
            },
            TestEntry {
                flags: HAS_METADATA_HANDLE | HAS_ENTRYPOINT | NEEDS_PARAMETER_INTERPRETATION,
                method_reference: first.0,
                declaring_type_index: 2,
                entrypoint_index: second_index,
            },
        ]);
        attach_blob(&header, &mut methods, &blob)?;
        let method: &AotMethod = methods
            .iter()
            .find(|method: &&AotMethod| method.record_offset == first.0)
            .ok_or_else(|| invalid(0, "test method mapping is unmatched"))?;
        assert_eq!(method.entrypoint_rva, None);
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
            resolve_fixup(&[0, 0, 0, 0], target, address_base, &file, 0).map(|_: u32| ()),
            "executable code",
        );
        Ok(())
    }
}
