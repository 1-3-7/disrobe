use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::metadata_records::invalid_metadata;
use super::native_hashtable;
use super::{
    AotContainer, AotSection, ReadyToRunHeader, container_section_bytes, open_container,
    unique_section,
};

const RESOURCE_INDEX_SECTION_ID: i32 = 324;
const RESOURCE_DATA_SECTION_ID: i32 = 325;
const MAX_RESOURCE_INDEX_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESOURCES: usize = 65_536;
const MAX_RESOURCE_STRING_BYTES: usize = 4_096;
const MAX_RESOURCE_DECODED_STRING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AotResourceStatus {
    #[default]
    NotPresent,
    Recovered,
    Rejected {
        section_offset: Option<u32>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AotResourceIndex {
    pub status: AotResourceStatus,
    pub resources: Vec<AotManifestResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<AotResourceRefusal>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AotManifestResource {
    pub assembly: String,
    pub name: String,
    pub data_offset: u32,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotResourceRefusal {
    pub entry_offset: u32,
    pub assembly: Option<String>,
    pub name: Option<String>,
    pub reason: String,
}

struct DecodedEntry {
    entry_offset: usize,
    resource: AotManifestResource,
}

fn invalid(at: usize, reason: &'static str) -> crate::error::Error {
    invalid_metadata(at, reason)
}

fn read_string(bytes: &[u8], at: &mut usize, budget: &mut usize) -> crate::error::Result<String> {
    let start: usize = *at;
    let length: u32 = native_hashtable::decode_unsigned(bytes, at, invalid)?;
    let length: usize = usize::try_from(length).map_err(|_: std::num::TryFromIntError| {
        invalid(start, "resource string length does not fit usize")
    })?;
    if length > MAX_RESOURCE_STRING_BYTES {
        return Err(invalid(start, "resource string exceeds parser limit"));
    }
    *budget = budget
        .checked_add(length)
        .ok_or_else(|| invalid(start, "resource decoded string budget overflowed"))?;
    if *budget > MAX_RESOURCE_DECODED_STRING_BYTES {
        return Err(invalid(
            start,
            "resource decoded strings exceed parser limit",
        ));
    }
    let end: usize = at
        .checked_add(length)
        .ok_or_else(|| invalid(start, "resource string end overflowed"))?;
    let value: &[u8] = bytes
        .get(*at..end)
        .ok_or_else(|| invalid(start, "resource string exceeds the index"))?;
    let value: &str = std::str::from_utf8(value)
        .map_err(|_: std::str::Utf8Error| invalid(start, "resource string is not UTF-8"))?;
    *at = end;
    Ok(value.to_owned())
}

fn decode_entry(
    index: &[u8],
    entry_offset: usize,
    data_length: usize,
    budget: &mut usize,
) -> Result<DecodedEntry, AotResourceRefusal> {
    let entry_at: u32 = u32::try_from(entry_offset).map_or(u32::MAX, |value: u32| value);
    let refuse = |assembly: Option<&str>, name: Option<&str>, error: crate::error::Error| {
        AotResourceRefusal {
            entry_offset: entry_at,
            assembly: assembly.map(str::to_owned),
            name: name.map(str::to_owned),
            reason: error.to_string(),
        }
    };
    let mut cursor: usize = entry_offset;
    let assembly: String = read_string(index, &mut cursor, budget)
        .map_err(|error: crate::error::Error| refuse(None, None, error))?;
    let name: String = read_string(index, &mut cursor, budget)
        .map_err(|error: crate::error::Error| refuse(Some(&assembly), None, error))?;
    let data_offset: u32 = native_hashtable::decode_unsigned(index, &mut cursor, invalid)
        .map_err(|error: crate::error::Error| refuse(Some(&assembly), Some(&name), error))?;
    let length: u32 = native_hashtable::decode_unsigned(index, &mut cursor, invalid)
        .map_err(|error: crate::error::Error| refuse(Some(&assembly), Some(&name), error))?;
    let end: Option<usize> = usize::try_from(data_offset)
        .ok()
        .zip(usize::try_from(length).ok())
        .and_then(|(start, size): (usize, usize)| start.checked_add(size));
    if end.is_none_or(|end: usize| end > data_length) {
        return Err(refuse(
            Some(&assembly),
            Some(&name),
            invalid(entry_offset, "resource data range is outside the data blob"),
        ));
    }
    Ok(DecodedEntry {
        entry_offset,
        resource: AotManifestResource {
            assembly,
            name,
            data_offset,
            length,
        },
    })
}

fn recover(image: &[u8], header: &ReadyToRunHeader) -> crate::error::Result<AotResourceIndex> {
    let Some(index_section): Option<&AotSection> =
        unique_section(header, RESOURCE_INDEX_SECTION_ID, invalid)?
    else {
        return Ok(AotResourceIndex::default());
    };
    let data_section: &AotSection = unique_section(header, RESOURCE_DATA_SECTION_ID, invalid)?
        .ok_or_else(|| invalid(0, "resource index has no resource data section"))?;
    let container: AotContainer<'_> = open_container(image)?;
    let index: &[u8] = container_section_bytes(image, &container, index_section, invalid)?;
    if index.len() > MAX_RESOURCE_INDEX_BYTES {
        return Err(invalid(0, "resource index exceeds parser byte limit"));
    }
    let data: &[u8] = container_section_bytes(image, &container, data_section, invalid)?;
    let offsets: Vec<usize> = native_hashtable::entry_offsets(index, MAX_RESOURCES, invalid)?;
    let mut refusals: Vec<AotResourceRefusal> = Vec::new();
    let mut decoded_string_bytes: usize = 0;
    let mut by_name: BTreeMap<(String, String), Vec<DecodedEntry>> = BTreeMap::new();
    for offset in offsets {
        match decode_entry(index, offset, data.len(), &mut decoded_string_bytes) {
            Ok(entry) => by_name
                .entry((entry.resource.assembly.clone(), entry.resource.name.clone()))
                .or_default()
                .push(entry),
            Err(refusal) => refusals.push(refusal),
        }
    }
    let mut resources: Vec<AotManifestResource> = Vec::new();
    for ((assembly, name), entries) in by_name {
        let Some(first): Option<&DecodedEntry> = entries.first() else {
            continue;
        };
        if entries
            .iter()
            .all(|entry: &DecodedEntry| entry.resource == first.resource)
        {
            resources.push(first.resource.clone());
            continue;
        }
        for entry in &entries {
            refusals.push(AotResourceRefusal {
                entry_offset: u32::try_from(entry.entry_offset)
                    .map_or(u32::MAX, |value: u32| value),
                assembly: Some(assembly.clone()),
                name: Some(name.clone()),
                reason: invalid(
                    entry.entry_offset,
                    "resource index gives one resource name different data ranges",
                )
                .to_string(),
            });
        }
    }
    refusals.sort_by_key(|refusal: &AotResourceRefusal| refusal.entry_offset);
    Ok(AotResourceIndex {
        status: AotResourceStatus::Recovered,
        resources,
        refusals,
    })
}

#[must_use]
pub fn recover_manifest_resources(image: &[u8], header: &ReadyToRunHeader) -> AotResourceIndex {
    recover(image, header).unwrap_or_else(|error: crate::error::Error| {
        let section_offset: Option<u32> = match &error {
            crate::error::Error::InvalidAotMetadata { offset, .. } => Some(*offset),
            _ => None,
        };
        AotResourceIndex {
            status: AotResourceStatus::Rejected {
                section_offset,
                reason: error.to_string(),
            },
            resources: Vec::new(),
            refusals: Vec::new(),
        }
    })
}

pub fn manifest_resource_data<'a>(
    image: &'a [u8],
    header: &ReadyToRunHeader,
    resource: &AotManifestResource,
) -> crate::error::Result<&'a [u8]> {
    let data_section: &AotSection = unique_section(header, RESOURCE_DATA_SECTION_ID, invalid)?
        .ok_or_else(|| invalid(0, "image has no resource data section"))?;
    let container: AotContainer<'_> = open_container(image)?;
    let data: &'a [u8] = container_section_bytes(image, &container, data_section, invalid)?;
    let start: usize =
        usize::try_from(resource.data_offset).map_err(|_: std::num::TryFromIntError| {
            invalid(0, "resource data offset does not fit usize")
        })?;
    let length: usize = usize::try_from(resource.length)
        .map_err(|_: std::num::TryFromIntError| invalid(0, "resource length does not fit usize"))?;
    let end: usize = start
        .checked_add(length)
        .ok_or_else(|| invalid(start, "resource data end overflowed"))?;
    data.get(start..end)
        .ok_or_else(|| invalid(start, "resource data range is outside the data blob"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_string_budget_charges_aliases_and_failed_following_fields() {
        let encoded: [u8; 2] = [2, b'a'];
        let mut exact: usize = MAX_RESOURCE_DECODED_STRING_BYTES - 1;
        let mut cursor: usize = 0;
        assert!(matches!(
            read_string(&encoded, &mut cursor, &mut exact),
            Ok(value) if value == "a"
        ));
        assert_eq!(exact, MAX_RESOURCE_DECODED_STRING_BYTES);
        let mut next_cursor: usize = 0;
        assert!(read_string(&encoded, &mut next_cursor, &mut exact).is_err());
        assert_eq!(exact, MAX_RESOURCE_DECODED_STRING_BYTES + 1);

        let truncated_following: [u8; 3] = [2, b'a', 2];
        let mut charged: usize = 0;
        assert!(decode_entry(&truncated_following, 0, 0, &mut charged).is_err());
        assert_eq!(charged, 2);
    }
}
