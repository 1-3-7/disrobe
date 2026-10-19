use serde::{Deserialize, Serialize};

use super::invoke_map::resolve_runtime_type_fixup;
use super::metadata_records::{AotRuntimeFieldLayout, AotTypeLayout};
use super::native_hashtable;
use super::{
    AotContainer, AotSection, ReadyToRunHeader, container_section_bytes, open_container,
    unique_section,
};

const FIELD_MAP_SECTION_ID: i32 = 309;
const COMMON_FIXUPS_SECTION_ID: i32 = 308;
const MAX_FIELD_MAP_BYTES: usize = 64 * 1024 * 1024;
const MAX_FIELD_MAP_ENTRIES: usize = 1_048_576;
const MAX_FIELD_NAME_BYTES: usize = 4_096;
const STORAGE_CLASS_MASK: u32 = 0x03;
const INSTANCE_FIELD: u32 = 0x00;
const UNIVERSAL_CANONICAL_ENTRY: u32 = 0x04;
const HAS_METADATA_HANDLE: u32 = 0x08;
const OFFSET_ENCODED_DIRECTLY: u32 = 0x20;
const KNOWN_FLAGS: u32 = STORAGE_CLASS_MASK
    | HAS_METADATA_HANDLE
    | UNIVERSAL_CANONICAL_ENTRY
    | OFFSET_ENCODED_DIRECTLY
    | 0x40
    | 0x80;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotFieldMapRefusal {
    pub entry_offset: Option<u32>,
    pub field_record_offset: Option<u32>,
    pub reason: String,
}

fn invalid(at: usize, reason: &'static str) -> crate::error::Error {
    crate::error::Error::InvalidAotFieldMap {
        offset: u32::try_from(at).map_or(u32::MAX, |value: u32| value),
        reason,
    }
}

fn refusal(
    entry_offset: Option<usize>,
    field_record_offset: Option<u32>,
    error: crate::error::Error,
) -> AotFieldMapRefusal {
    AotFieldMapRefusal {
        entry_offset: entry_offset
            .map(|offset: usize| u32::try_from(offset).map_or(u32::MAX, |value: u32| value)),
        field_record_offset,
        reason: error.to_string(),
    }
}

fn field_name(bytes: &[u8], cursor: &mut usize) -> crate::error::Result<String> {
    let length_at: usize = *cursor;
    let length: usize = usize::try_from(native_hashtable::decode_unsigned(bytes, cursor, invalid)?)
        .map_err(|_: std::num::TryFromIntError| {
            invalid(length_at, "field-map name length does not fit usize")
        })?;
    if length == 0 || length > MAX_FIELD_NAME_BYTES {
        return Err(invalid(
            length_at,
            "field-map name length is outside parser bounds",
        ));
    }
    let end: usize = cursor
        .checked_add(length)
        .filter(|end: &usize| *end <= bytes.len())
        .ok_or_else(|| invalid(length_at, "field-map name is truncated"))?;
    let value: &str = std::str::from_utf8(&bytes[*cursor..end])
        .map_err(|_: std::str::Utf8Error| invalid(length_at, "field-map name is not UTF-8"))?;
    *cursor = end;
    Ok(value.to_owned())
}

fn recover(
    image: &[u8],
    header: &ReadyToRunHeader,
    layouts: &[AotTypeLayout],
) -> crate::error::Result<(Vec<AotFieldMapRefusal>, Vec<AotRuntimeFieldLayout>)> {
    let Some(field_section): Option<&AotSection> =
        unique_section(header, FIELD_MAP_SECTION_ID, invalid)?
    else {
        return Ok((Vec::new(), Vec::new()));
    };
    let fixups_section: &AotSection = unique_section(header, COMMON_FIXUPS_SECTION_ID, invalid)?
        .ok_or_else(|| invalid(0, "field map has no common-fixups section"))?;
    let container: AotContainer<'_> = open_container(image)?;
    let field_bytes: &[u8] = container_section_bytes(image, &container, field_section, invalid)?;
    let fixup_bytes: &[u8] = container_section_bytes(image, &container, fixups_section, invalid)?;
    if field_bytes.len() > MAX_FIELD_MAP_BYTES {
        return Err(invalid(0, "field-map blob exceeds parser byte limit"));
    }
    let offsets: Vec<usize> =
        native_hashtable::entry_offsets(field_bytes, MAX_FIELD_MAP_ENTRIES, invalid)?;
    let mut owners: Vec<(u32, u32)> = layouts
        .iter()
        .flat_map(|layout: &AotTypeLayout| {
            layout
                .instance_fields
                .iter()
                .map(|field| (field.record_offset, layout.record_offset))
        })
        .collect();
    owners.sort_unstable();
    owners.dedup();
    let mut refusals: Vec<AotFieldMapRefusal> = Vec::new();
    let mut recovered: Vec<AotRuntimeFieldLayout> = Vec::new();
    recovered
        .try_reserve_exact(offsets.len())
        .map_err(|_| invalid(0, "runtime field layout allocation failed"))?;
    for entry_offset in offsets {
        let mut cursor: usize = entry_offset;
        let mut runtime_type_error: Option<(u32, crate::error::Error)> = None;
        let parsed = (|| -> crate::error::Result<Option<AotRuntimeFieldLayout>> {
            let flags: u32 = native_hashtable::decode_unsigned(field_bytes, &mut cursor, invalid)?;
            if flags & !KNOWN_FLAGS != 0 {
                return Err(invalid(
                    entry_offset,
                    "field-map flags contain unknown bits",
                ));
            }
            let declaring_type_index: u32 =
                native_hashtable::decode_unsigned(field_bytes, &mut cursor, invalid)?;
            let field_record_offset: u32 =
                if header.major_version < 16 && flags & HAS_METADATA_HANDLE == 0 {
                    let name: String = field_name(field_bytes, &mut cursor)?;
                    let mut matching: Vec<u32> = layouts
                        .iter()
                        .flat_map(|layout: &AotTypeLayout| layout.instance_fields.iter())
                        .filter(|field| field.name == name)
                        .map(|field| field.record_offset)
                        .collect();
                    matching.sort_unstable();
                    matching.dedup();
                    let [field_record_offset] = matching.as_slice() else {
                        return Err(invalid(
                            entry_offset,
                            "name-based field-map entry does not have exactly one metadata field",
                        ));
                    };
                    *field_record_offset
                } else {
                    native_hashtable::decode_unsigned(field_bytes, &mut cursor, invalid)?
                };
            if flags & STORAGE_CLASS_MASK != INSTANCE_FIELD {
                return Ok(None);
            }
            if flags & OFFSET_ENCODED_DIRECTLY == 0 {
                return Err(invalid(
                    entry_offset,
                    "instance field offset is not encoded directly",
                ));
            }
            if flags & UNIVERSAL_CANONICAL_ENTRY != 0 {
                return Err(invalid(
                    entry_offset,
                    "universal-canonical field-map entry carries an ordinal",
                ));
            }
            let field_offset: u32 =
                native_hashtable::decode_unsigned(field_bytes, &mut cursor, invalid)?;
            let owner_start: usize = owners.partition_point(|(field_offset, _type_offset)| {
                *field_offset < field_record_offset
            });
            let owner_end: usize = owners.partition_point(|(field_offset, _type_offset)| {
                *field_offset <= field_record_offset
            });
            let [(_field_offset, type_record_offset)] = owners
                .get(owner_start..owner_end)
                .ok_or_else(|| invalid(entry_offset, "metadata field owner range is invalid"))?
            else {
                return Err(invalid(
                    entry_offset,
                    "field-map field does not have exactly one metadata owner",
                ));
            };
            let method_table_rva: Option<u32> = match resolve_runtime_type_fixup(
                fixup_bytes,
                container.address_base + u64::from(fixups_section.start_rva),
                container.address_base,
                &container.file,
                declaring_type_index,
                invalid,
            ) {
                Ok(rva) => Some(rva),
                Err(error) => {
                    runtime_type_error = Some((field_record_offset, error));
                    None
                }
            };
            Ok(Some(AotRuntimeFieldLayout {
                type_record_offset: *type_record_offset,
                field_record_offset,
                method_table_rva,
                field_offset,
            }))
        })();
        match parsed {
            Ok(Some(layout)) => {
                recovered.push(layout);
                if let Some((field_record_offset, error)) = runtime_type_error {
                    refusals.push(refusal(
                        Some(entry_offset),
                        Some(field_record_offset),
                        error,
                    ));
                }
            }
            Ok(None) => {}
            Err(error) => refusals.push(refusal(Some(entry_offset), None, error)),
        }
    }
    recovered.sort_unstable();
    recovered.dedup();
    Ok((refusals, recovered))
}

pub(super) fn recover_field_map(
    image: &[u8],
    header: &ReadyToRunHeader,
    layouts: &[AotTypeLayout],
) -> (Vec<AotFieldMapRefusal>, Vec<AotRuntimeFieldLayout>) {
    recover(image, header, layouts)
        .unwrap_or_else(|error: crate::error::Error| (vec![refusal(None, None, error)], Vec::new()))
}
