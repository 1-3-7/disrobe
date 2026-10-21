use std::collections::BTreeMap;

use disrobe_bytes::{read_i32_le_at, read_u32_le_at};
use object::{Object as _, ObjectSection as _, SectionKind};
use serde::{Deserialize, Serialize};

use super::metadata_records::{
    HANDLE_ARRAY_SIGNATURE, HANDLE_BY_REFERENCE_SIGNATURE, HANDLE_METHOD_TYPE_VARIABLE_SIGNATURE,
    HANDLE_MODIFIED_TYPE, HANDLE_NAMESPACE_DEFINITION, HANDLE_NAMESPACE_REFERENCE,
    HANDLE_POINTER_SIGNATURE, HANDLE_SCOPE_DEFINITION, HANDLE_SCOPE_REFERENCE,
    HANDLE_SZ_ARRAY_SIGNATURE, HANDLE_TYPE_DEFINITION, HANDLE_TYPE_INSTANTIATION_SIGNATURE,
    HANDLE_TYPE_REFERENCE, HANDLE_TYPE_SPECIFICATION, HANDLE_TYPE_VARIABLE_SIGNATURE,
    MetadataBudget, MetadataCursor, RawHandle, SerializedHandleEncoding, handle_encoding_for,
    invalid_metadata, metadata_section, metadata_section_bytes,
};
use super::method_boundaries::runtime_function_ranges;
use super::{
    AotCodeRange, AotContainer, AotSection, ReadyToRunHeader, address_range_is_inside,
    container_section_bytes, decode_metadata_unsigned, open_container, unique_section,
};

const STACK_TRACE_MAP_SECTION_ID: i32 = 327;
const UPDATE_OWNING_TYPE: u8 = 0x01;
const UPDATE_NAME: u8 = 0x02;
const UPDATE_SIGNATURE: u8 = 0x04;
const UPDATE_GENERIC_SIGNATURE: u8 = 0x08;
const IS_STACK_TRACE_HIDDEN: u8 = 0x10;
const KNOWN_COMMAND_BITS: u8 = 0x1f;
const HANDLE_CONSTANT_STRING_ARRAY: u8 = 0x19;
const HANDLE_CONSTANT_STRING_VALUE: u8 = 0x1a;
const MIN_ENTRY_BYTES: usize = 5;
const MAX_STACK_TRACE_MAP_BYTES: usize = 64 * 1024 * 1024;
const MAX_STACK_TRACE_ENTRIES: usize = 4_194_304;
const INITIAL_ENTRY_CAPACITY: usize = 65_536;
const MAX_NAME_DEPTH: usize = 64;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_NAME_RECORDS: usize = 4_194_304;
const MAX_STRING_STORAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AotStackTraceStatus {
    #[default]
    NotPresent,
    UnsupportedVersion {
        major_version: u16,
        minor_version: u16,
    },
    Recovered,
    Rejected {
        section_offset: Option<u32>,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AotStackTraceMap {
    pub status: AotStackTraceStatus,
    pub methods: Vec<AotStackTraceMethod>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<AotStackTraceRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_range_refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStackTraceMethod {
    pub rva: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_range: Option<AotCodeRange>,
    pub stack_trace_hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<AotStackTraceName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStackTraceName {
    pub owning_type_token: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owning_type_record_offset: Option<u32>,
    pub namespace: Option<String>,
    pub type_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub type_arguments: Vec<String>,
    pub method_name: String,
    pub signature_record_offset: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method_generic_arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotStackTraceRefusal {
    pub entry_offset: u32,
    pub rva: Option<u32>,
    pub reason: String,
}

impl AotStackTraceMap {
    fn rejected(error: &crate::error::Error) -> Self {
        let section_offset: Option<u32> = match error {
            crate::error::Error::InvalidAotMetadata { offset, .. } => Some(*offset),
            _ => None,
        };
        Self {
            status: AotStackTraceStatus::Rejected {
                section_offset,
                reason: error.to_string(),
            },
            methods: Vec::new(),
            refusals: Vec::new(),
            code_range_refusal: None,
        }
    }
}

#[derive(Debug, Clone)]
struct OwnerName {
    namespace: Option<String>,
    type_name: String,
    type_arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct CommandState {
    owning_type: u32,
    name: u32,
    signature: u32,
    method_instantiation: u32,
}

fn executable_rva(container: &AotContainer<'_>, rva: u32) -> bool {
    let Some(address): Option<u64> = container.address_base.checked_add(u64::from(rva)) else {
        return false;
    };
    container.file.sections().any(|section| {
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
        address_range_is_inside(address, address, start, end)
    })
}

struct NameResolver<'a> {
    metadata: &'a [u8],
    encoding: SerializedHandleEncoding,
    budget: MetadataBudget,
    strings: BTreeMap<u32, String>,
    string_bytes: usize,
    records: usize,
    output_bytes: usize,
    namespaces: BTreeMap<(u8, u32), Option<String>>,
    types: BTreeMap<(u8, u32), OwnerName>,
    string_arrays: BTreeMap<u32, Vec<String>>,
    owners: BTreeMap<u32, Result<OwnerName, String>>,
}

impl<'a> NameResolver<'a> {
    const fn new(metadata: &'a [u8], encoding: SerializedHandleEncoding) -> Self {
        Self {
            metadata,
            encoding,
            budget: MetadataBudget::new(),
            strings: BTreeMap::new(),
            string_bytes: 0,
            records: 0,
            output_bytes: 0,
            namespaces: BTreeMap::new(),
            types: BTreeMap::new(),
            string_arrays: BTreeMap::new(),
            owners: BTreeMap::new(),
        }
    }

    fn cursor(&mut self, raw: RawHandle) -> crate::error::Result<MetadataCursor<'a>> {
        self.records = self.records.checked_add(1).ok_or_else(|| {
            invalid_metadata(offset_of(raw.offset), "stack-trace name work overflowed")
        })?;
        if self.records > MAX_NAME_RECORDS {
            return Err(invalid_metadata(
                offset_of(raw.offset),
                "stack-trace name work exceeds the parser limit",
            ));
        }
        MetadataCursor::new(self.metadata, raw.offset, self.encoding)
    }

    fn claim_output(&mut self, bytes: usize, at: u32) -> crate::error::Result<()> {
        self.output_bytes = self
            .output_bytes
            .checked_add(bytes)
            .filter(|total: &usize| *total <= MAX_OUTPUT_BYTES)
            .ok_or_else(|| {
                invalid_metadata(offset_of(at), "stack-trace names exceed the output limit")
            })?;
        Ok(())
    }

    fn string(&mut self, offset: u32) -> crate::error::Result<String> {
        if offset == 0 {
            return Err(invalid_metadata(0, "stack-trace name string handle is nil"));
        }
        if let Some(value) = self.strings.get(&offset) {
            return Ok(value.clone());
        }
        let at: usize = offset_of(offset);
        let (length, width): (u32, usize) = decode_metadata_unsigned(self.metadata, at)
            .ok_or_else(|| invalid_metadata(at, "metadata string length is malformed"))?;
        let length: usize = usize::try_from(length).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(at, "metadata string length does not fit usize")
        })?;
        if length > MAX_NAME_BYTES {
            return Err(invalid_metadata(
                at,
                "metadata string length exceeds parser limit",
            ));
        }
        let start: usize = at
            .checked_add(width)
            .ok_or_else(|| invalid_metadata(at, "metadata string start overflowed"))?;
        let end: usize = start
            .checked_add(length)
            .ok_or_else(|| invalid_metadata(at, "metadata string end overflowed"))?;
        let bytes: &[u8] = self
            .metadata
            .get(start..end)
            .ok_or_else(|| invalid_metadata(at, "metadata string exceeds the section"))?;
        let value: &str = std::str::from_utf8(bytes).map_err(|_: std::str::Utf8Error| {
            invalid_metadata(at, "metadata string is not UTF-8")
        })?;
        if self.strings.len() >= MAX_NAME_RECORDS {
            return Err(invalid_metadata(
                at,
                "metadata string record count exceeds parser limit",
            ));
        }
        self.string_bytes = self
            .string_bytes
            .checked_add(value.len())
            .filter(|total: &usize| *total <= MAX_STRING_STORAGE_BYTES)
            .ok_or_else(|| invalid_metadata(at, "metadata string storage exceeds parser limit"))?;
        self.strings.insert(offset, value.to_owned());
        Ok(value.to_owned())
    }

    fn namespace(&mut self, raw: RawHandle, depth: usize) -> crate::error::Result<Option<String>> {
        if raw.offset == 0 || matches!(raw.kind, HANDLE_SCOPE_DEFINITION | HANDLE_SCOPE_REFERENCE) {
            return Ok(None);
        }
        if !matches!(
            raw.kind,
            HANDLE_NAMESPACE_DEFINITION | HANDLE_NAMESPACE_REFERENCE
        ) {
            return Err(invalid_metadata(
                offset_of(raw.offset),
                "namespace parent has an unsupported handle kind",
            ));
        }
        if let Some(value) = self.namespaces.get(&(raw.kind, raw.offset)) {
            return Ok(value.clone());
        }
        let next: usize = next_depth(raw.offset, depth)?;
        let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
        let parent: RawHandle = cursor.raw_handle()?;
        let name_offset: u32 = cursor.typed_handle()?;
        let name: String = if name_offset == 0 {
            String::new()
        } else {
            self.string(name_offset)?
        };
        let parent_name: Option<String> = self.namespace(parent, next)?;
        let qualified: Option<String> = match (parent_name, name.is_empty()) {
            (None, true) => None,
            (None, false) => Some(name),
            (Some(parent), true) => Some(parent),
            (Some(parent), false) => Some(bounded_join(&parent, ".", &name, raw.offset)?),
        };
        self.namespaces
            .insert((raw.kind, raw.offset), qualified.clone());
        Ok(qualified)
    }

    fn named_type(&mut self, raw: RawHandle, depth: usize) -> crate::error::Result<OwnerName> {
        if let Some(value) = self.types.get(&(raw.kind, raw.offset)) {
            return Ok(value.clone());
        }
        let next: usize = next_depth(raw.offset, depth)?;
        let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
        let resolved: OwnerName = match raw.kind {
            HANDLE_TYPE_DEFINITION => {
                let _flags: u32 = cursor.unsigned()?;
                let _base_type: RawHandle = cursor.raw_handle()?;
                let namespace: u32 = cursor.typed_handle()?;
                let name: String = self.string(cursor.typed_handle()?)?;
                let _size: u32 = cursor.unsigned()?;
                let _packing: u32 = cursor.unsigned()?;
                let enclosing: u32 = cursor.typed_handle()?;
                if enclosing == 0 {
                    OwnerName {
                        namespace: self.namespace(
                            RawHandle {
                                kind: HANDLE_NAMESPACE_DEFINITION,
                                offset: namespace,
                            },
                            next,
                        )?,
                        type_name: name,
                        type_arguments: Vec::new(),
                    }
                } else {
                    let outer: OwnerName = self.named_type(
                        RawHandle {
                            kind: HANDLE_TYPE_DEFINITION,
                            offset: enclosing,
                        },
                        next,
                    )?;
                    OwnerName {
                        type_name: bounded_join(&outer.type_name, "+", &name, raw.offset)?,
                        namespace: outer.namespace,
                        type_arguments: Vec::new(),
                    }
                }
            }
            HANDLE_TYPE_REFERENCE => {
                let parent: RawHandle = cursor.raw_handle()?;
                let name: String = self.string(cursor.typed_handle()?)?;
                if parent.kind == HANDLE_TYPE_REFERENCE && parent.offset != 0 {
                    let outer: OwnerName = self.named_type(parent, next)?;
                    OwnerName {
                        type_name: bounded_join(&outer.type_name, "+", &name, raw.offset)?,
                        namespace: outer.namespace,
                        type_arguments: Vec::new(),
                    }
                } else {
                    OwnerName {
                        namespace: self.namespace(parent, next)?,
                        type_name: name,
                        type_arguments: Vec::new(),
                    }
                }
            }
            _ => {
                return Err(invalid_metadata(
                    offset_of(raw.offset),
                    "named type has an unsupported handle kind",
                ));
            }
        };
        self.claim_output(
            resolved
                .type_name
                .len()
                .saturating_add(resolved.namespace.as_ref().map_or(0, String::len)),
            raw.offset,
        )?;
        self.types.insert((raw.kind, raw.offset), resolved.clone());
        Ok(resolved)
    }

    fn full_name(&mut self, raw: RawHandle, depth: usize) -> crate::error::Result<String> {
        let next: usize = next_depth(raw.offset, depth)?;
        match raw.kind {
            HANDLE_TYPE_DEFINITION | HANDLE_TYPE_REFERENCE => {
                let owner: OwnerName = self.named_type(raw, next)?;
                qualified_name(&owner, raw.offset)
            }
            HANDLE_TYPE_SPECIFICATION => {
                let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
                let signature: RawHandle = cursor.raw_handle()?;
                self.full_name(signature, next)
            }
            HANDLE_TYPE_INSTANTIATION_SIGNATURE => {
                let owner: OwnerName = self.instantiation(raw, next)?;
                qualified_name(&owner, raw.offset)
            }
            HANDLE_SZ_ARRAY_SIGNATURE
            | HANDLE_POINTER_SIGNATURE
            | HANDLE_BY_REFERENCE_SIGNATURE
            | HANDLE_ARRAY_SIGNATURE => {
                let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
                let element: RawHandle = cursor.raw_handle()?;
                let suffix: String = match raw.kind {
                    HANDLE_SZ_ARRAY_SIGNATURE => "[]".to_owned(),
                    HANDLE_POINTER_SIGNATURE => "*".to_owned(),
                    HANDLE_BY_REFERENCE_SIGNATURE => "&".to_owned(),
                    _ => {
                        let rank: i32 = cursor.signed()?;
                        let commas: usize = usize::try_from(rank)
                            .ok()
                            .and_then(|rank: usize| rank.checked_sub(1))
                            .filter(|commas: &usize| *commas < MAX_NAME_BYTES)
                            .ok_or_else(|| {
                                invalid_metadata(
                                    offset_of(raw.offset),
                                    "array signature rank is invalid",
                                )
                            })?;
                        format!("[{}]", ",".repeat(commas))
                    }
                };
                let element_name: String = self.full_name(element, next)?;
                bounded_join(&element_name, "", &suffix, raw.offset)
            }
            HANDLE_TYPE_VARIABLE_SIGNATURE | HANDLE_METHOD_TYPE_VARIABLE_SIGNATURE => {
                let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
                let number: i32 = cursor.signed()?;
                if number < 0 {
                    return Err(invalid_metadata(
                        offset_of(raw.offset),
                        "type variable signature number is negative",
                    ));
                }
                let prefix: &str = if raw.kind == HANDLE_TYPE_VARIABLE_SIGNATURE {
                    "!"
                } else {
                    "!!"
                };
                Ok(format!("{prefix}{number}"))
            }
            HANDLE_MODIFIED_TYPE => {
                let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
                let _is_optional: u32 = cursor.unsigned()?;
                let _modifier: RawHandle = cursor.raw_handle()?;
                let modified: RawHandle = cursor.raw_handle()?;
                self.full_name(modified, next)
            }
            _ => Err(invalid_metadata(
                offset_of(raw.offset),
                "stack-trace type name has an unsupported handle kind",
            )),
        }
    }

    fn instantiation(&mut self, raw: RawHandle, depth: usize) -> crate::error::Result<OwnerName> {
        let next: usize = next_depth(raw.offset, depth)?;
        let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
        let generic_type: RawHandle = cursor.raw_handle()?;
        let arguments: Vec<RawHandle> = cursor.raw_collection(&mut self.budget)?;
        let definition: OwnerName = match generic_type.kind {
            HANDLE_TYPE_DEFINITION | HANDLE_TYPE_REFERENCE => {
                self.named_type(generic_type, next)?
            }
            _ => {
                return Err(invalid_metadata(
                    offset_of(raw.offset),
                    "generic instantiation names an unsupported generic type",
                ));
            }
        };
        let mut type_arguments: Vec<String> = Vec::new();
        type_arguments.try_reserve_exact(arguments.len()).map_err(
            |_: std::collections::TryReserveError| {
                invalid_metadata(offset_of(raw.offset), "type argument allocation failed")
            },
        )?;
        let mut rendered_bytes: usize = definition.type_name.len();
        for argument in arguments {
            let argument_name: String = self.full_name(argument, next)?;
            rendered_bytes = rendered_bytes
                .saturating_add(argument_name.len())
                .saturating_add(1);
            if rendered_bytes > MAX_NAME_BYTES {
                return Err(invalid_metadata(
                    offset_of(raw.offset),
                    "stack-trace type name exceeds parser limit",
                ));
            }
            type_arguments.push(argument_name);
        }
        Ok(OwnerName {
            namespace: definition.namespace,
            type_name: definition.type_name,
            type_arguments,
        })
    }

    fn owner(&mut self, token: u32) -> Result<OwnerName, String> {
        if let Some(cached) = self.owners.get(&token) {
            return cached.clone();
        }
        let (kind, offset): (u32, u32) = self.encoding.split_token(token);
        let resolved: Result<OwnerName, String> = u8::try_from(kind)
            .map_err(|_: std::num::TryFromIntError| {
                invalid_metadata(offset_of(offset), "owning type token kind does not fit u8")
            })
            .and_then(|kind: u8| {
                let raw: RawHandle = RawHandle { kind, offset };
                match kind {
                    HANDLE_TYPE_DEFINITION | HANDLE_TYPE_REFERENCE => self.named_type(raw, 0),
                    HANDLE_TYPE_SPECIFICATION => {
                        let mut cursor: MetadataCursor<'a> = self.cursor(raw)?;
                        let signature: RawHandle = cursor.raw_handle()?;
                        if signature.kind == HANDLE_TYPE_INSTANTIATION_SIGNATURE {
                            self.instantiation(signature, 1)
                        } else {
                            Ok(OwnerName {
                                namespace: None,
                                type_name: self.full_name(signature, 1)?,
                                type_arguments: Vec::new(),
                            })
                        }
                    }
                    _ => Err(invalid_metadata(
                        offset_of(offset),
                        "owning type token has an unsupported handle kind",
                    )),
                }
            })
            .map_err(|error: crate::error::Error| error.to_string());
        self.owners.insert(token, resolved.clone());
        resolved
    }

    fn method_instantiation(&mut self, offset: u32) -> crate::error::Result<Vec<String>> {
        if offset == 0 {
            return Ok(Vec::new());
        }
        if let Some(cached) = self.string_arrays.get(&offset) {
            return Ok(cached.clone());
        }
        let mut cursor: MetadataCursor<'a> = self.cursor(RawHandle {
            kind: HANDLE_CONSTANT_STRING_ARRAY,
            offset,
        })?;
        let values: Vec<RawHandle> = cursor.raw_collection(&mut self.budget)?;
        let mut names: Vec<String> = Vec::new();
        names
            .try_reserve_exact(values.len())
            .map_err(|_: std::collections::TryReserveError| {
                invalid_metadata(offset_of(offset), "method instantiation allocation failed")
            })?;
        for value in values {
            if value.kind != HANDLE_CONSTANT_STRING_VALUE {
                return Err(invalid_metadata(
                    offset_of(offset),
                    "method instantiation names a non-string handle",
                ));
            }
            names.push(self.string(value.offset)?);
        }
        self.string_arrays.insert(offset, names.clone());
        Ok(names)
    }

    fn name(&mut self, state: CommandState) -> Result<AotStackTraceName, String> {
        let owner: OwnerName = self.owner(state.owning_type)?;
        let method_name: String = self
            .string(state.name)
            .map_err(|error: crate::error::Error| error.to_string())?;
        let method_generic_arguments: Vec<String> = self
            .method_instantiation(state.method_instantiation)
            .map_err(|error: crate::error::Error| error.to_string())?;
        let size: usize = method_generic_arguments
            .iter()
            .chain(owner.type_arguments.iter())
            .map(String::len)
            .fold(owner.type_name.len(), usize::saturating_add)
            .saturating_add(method_name.len())
            .saturating_add(owner.namespace.as_ref().map_or(0, String::len));
        self.claim_output(size, state.name)
            .map_err(|error: crate::error::Error| error.to_string())?;
        let (owning_kind, owning_offset): (u32, u32) = self.encoding.split_token(state.owning_type);
        Ok(AotStackTraceName {
            owning_type_token: state.owning_type,
            owning_type_record_offset: (owning_kind == u32::from(HANDLE_TYPE_DEFINITION))
                .then_some(owning_offset),
            namespace: owner.namespace,
            type_name: owner.type_name,
            type_arguments: owner.type_arguments,
            method_name,
            signature_record_offset: state.signature,
            method_generic_arguments,
        })
    }
}

fn qualified_name(owner: &OwnerName, at: u32) -> crate::error::Result<String> {
    let base: String = match &owner.namespace {
        Some(namespace) => bounded_join(namespace, ".", &owner.type_name, at)?,
        None => owner.type_name.clone(),
    };
    if owner.type_arguments.is_empty() {
        return Ok(base);
    }
    let arguments: String = owner.type_arguments.join(",");
    let opened: String = bounded_join(&base, "<", &arguments, at)?;
    bounded_join(&opened, "", ">", at)
}

fn offset_of(offset: u32) -> usize {
    usize::try_from(offset).map_or(usize::MAX, |value: usize| value)
}

fn next_depth(offset: u32, depth: usize) -> crate::error::Result<usize> {
    let next: usize = depth
        .checked_add(1)
        .ok_or_else(|| invalid_metadata(offset_of(offset), "stack-trace name depth overflowed"))?;
    if next > MAX_NAME_DEPTH {
        return Err(invalid_metadata(
            offset_of(offset),
            "stack-trace name nesting exceeds the depth limit",
        ));
    }
    Ok(next)
}

fn bounded_join(left: &str, separator: &str, right: &str, at: u32) -> crate::error::Result<String> {
    let length: usize = left
        .len()
        .checked_add(separator.len())
        .and_then(|length: usize| length.checked_add(right.len()))
        .filter(|length: &usize| *length <= MAX_NAME_BYTES)
        .ok_or_else(|| {
            invalid_metadata(offset_of(at), "stack-trace type name exceeds parser limit")
        })?;
    let mut joined: String = String::with_capacity(length);
    joined.push_str(left);
    joined.push_str(separator);
    joined.push_str(right);
    Ok(joined)
}

fn invalid_map(at: usize, reason: &'static str) -> crate::error::Error {
    invalid_metadata(at, reason)
}

fn read_unsigned(bytes: &[u8], at: &mut usize) -> crate::error::Result<u32> {
    let (value, width): (u32, usize) = decode_metadata_unsigned(bytes, *at)
        .ok_or_else(|| invalid_map(*at, "stack-trace map unsigned value is malformed"))?;
    *at = at
        .checked_add(width)
        .ok_or_else(|| invalid_map(*at, "stack-trace map cursor overflowed"))?;
    Ok(value)
}

fn read_token(bytes: &[u8], at: &mut usize) -> crate::error::Result<u32> {
    let value: u32 = read_u32_le_at(bytes, *at).map_err(|_: disrobe_bytes::ByteReadError| {
        invalid_map(*at, "stack-trace map owning type token is truncated")
    })?;
    *at = at
        .checked_add(4)
        .ok_or_else(|| invalid_map(*at, "stack-trace map cursor overflowed"))?;
    Ok(value)
}

fn relative_target(map_start_rva: u32, at: usize, delta: i32) -> Option<u32> {
    let field: i64 = i64::from(map_start_rva).checked_add(i64::try_from(at).ok()?)?;
    u32::try_from(field.checked_add(i64::from(delta))?).ok()
}

fn recover(image: &[u8], header: &ReadyToRunHeader) -> crate::error::Result<AotStackTraceMap> {
    let Some(section): Option<&AotSection> =
        unique_section(header, STACK_TRACE_MAP_SECTION_ID, invalid_map)?
    else {
        return Ok(AotStackTraceMap::default());
    };
    let Some(encoding): Option<SerializedHandleEncoding> = handle_encoding_for(header) else {
        return Ok(AotStackTraceMap {
            status: AotStackTraceStatus::UnsupportedVersion {
                major_version: header.major_version,
                minor_version: header.minor_version,
            },
            methods: Vec::new(),
            refusals: Vec::new(),
            code_range_refusal: None,
        });
    };
    let metadata: &[u8] = match metadata_section(header)? {
        Some(metadata_section) => metadata_section_bytes(image, metadata_section)?,
        None => {
            return Err(invalid_map(
                0,
                "stack-trace map has no embedded metadata section",
            ));
        }
    };
    let container: AotContainer<'_> = open_container(image)?;
    let bytes: &[u8] = container_section_bytes(image, &container, section, invalid_map)?;
    if bytes.len() > MAX_STACK_TRACE_MAP_BYTES {
        return Err(invalid_map(0, "stack-trace map exceeds parser byte limit"));
    }
    let declared: i32 = read_i32_le_at(bytes, 0).map_err(|_: disrobe_bytes::ByteReadError| {
        invalid_map(0, "stack-trace map entry count is truncated")
    })?;
    let declared: usize = usize::try_from(declared).map_err(|_: std::num::TryFromIntError| {
        invalid_map(0, "stack-trace map entry count is negative")
    })?;
    let capacity: usize = bytes.len().saturating_sub(4) / MIN_ENTRY_BYTES;
    if declared > capacity || declared > MAX_STACK_TRACE_ENTRIES {
        return Err(invalid_map(
            0,
            "stack-trace map entry count exceeds the blob",
        ));
    }
    let (ranges, code_range_refusal): (Option<Vec<AotCodeRange>>, Option<String>) =
        match runtime_function_ranges(image) {
            Ok(ranges) => (ranges, None),
            Err(error) => (None, Some(error.to_string())),
        };
    let mut resolver: NameResolver<'_> = NameResolver::new(metadata, encoding);
    let mut methods: Vec<AotStackTraceMethod> = Vec::new();
    methods
        .try_reserve_exact(declared.min(INITIAL_ENTRY_CAPACITY))
        .map_err(|_: std::collections::TryReserveError| {
            invalid_map(0, "stack-trace map allocation failed")
        })?;
    let mut refusals: Vec<AotStackTraceRefusal> = Vec::new();
    let mut state: CommandState = CommandState::default();
    let mut cursor: usize = 4;
    let mut parsed: usize = 0;
    while cursor < bytes.len() {
        let entry_offset: usize = cursor;
        if parsed == declared {
            return Err(invalid_map(
                entry_offset,
                "stack-trace map has more entries than its header declares",
            ));
        }
        let command: u8 = *bytes
            .get(cursor)
            .ok_or_else(|| invalid_map(cursor, "stack-trace map command is truncated"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| invalid_map(entry_offset, "stack-trace map cursor overflowed"))?;
        if command & !KNOWN_COMMAND_BITS != 0 {
            return Err(invalid_map(
                entry_offset,
                "stack-trace map command has unknown bits",
            ));
        }
        if command & UPDATE_SIGNATURE != 0 && command & UPDATE_GENERIC_SIGNATURE != 0 {
            return Err(invalid_map(
                entry_offset,
                "stack-trace map command updates both signature forms",
            ));
        }
        if command & UPDATE_OWNING_TYPE != 0 {
            state.owning_type = read_token(bytes, &mut cursor)?;
        }
        if command & UPDATE_NAME != 0 {
            state.name = read_unsigned(bytes, &mut cursor)?;
        }
        if command & UPDATE_SIGNATURE != 0 {
            state.signature = read_unsigned(bytes, &mut cursor)?;
            state.method_instantiation = 0;
        }
        if command & UPDATE_GENERIC_SIGNATURE != 0 {
            state.signature = read_unsigned(bytes, &mut cursor)?;
            state.method_instantiation = read_unsigned(bytes, &mut cursor)?;
        }
        let delta: i32 =
            read_i32_le_at(bytes, cursor).map_err(|_: disrobe_bytes::ByteReadError| {
                invalid_map(cursor, "stack-trace map method pointer is truncated")
            })?;
        let pointer_at: usize = cursor;
        cursor = cursor
            .checked_add(4)
            .ok_or_else(|| invalid_map(entry_offset, "stack-trace map cursor overflowed"))?;
        parsed = parsed
            .checked_add(1)
            .ok_or_else(|| invalid_map(entry_offset, "stack-trace map entry count overflowed"))?;
        let entry_at: u32 = u32::try_from(entry_offset).map_or(u32::MAX, |value: u32| value);
        let Some(rva): Option<u32> = relative_target(section.start_rva, pointer_at, delta)
            .filter(|rva: &u32| executable_rva(&container, *rva))
        else {
            refusals.push(AotStackTraceRefusal {
                entry_offset: entry_at,
                rva: None,
                reason: invalid_map(
                    entry_offset,
                    "stack-trace method pointer does not resolve into executable code",
                )
                .to_string(),
            });
            continue;
        };
        let hidden: bool = command & IS_STACK_TRACE_HIDDEN != 0;
        let name: Option<AotStackTraceName> = if state.owning_type == 0 && hidden {
            None
        } else if state.owning_type == 0 {
            refusals.push(AotStackTraceRefusal {
                entry_offset: entry_at,
                rva: Some(rva),
                reason: invalid_map(entry_offset, "visible stack-trace entry has no owning type")
                    .to_string(),
            });
            None
        } else {
            match resolver.name(state) {
                Ok(name) => Some(name),
                Err(reason) => {
                    refusals.push(AotStackTraceRefusal {
                        entry_offset: entry_at,
                        rva: Some(rva),
                        reason,
                    });
                    None
                }
            }
        };
        let code_range: Option<AotCodeRange> = ranges.as_ref().and_then(|ranges| {
            ranges
                .binary_search_by_key(&rva, |range: &AotCodeRange| range.start_rva)
                .ok()
                .and_then(|index: usize| ranges.get(index).copied())
        });
        methods.push(AotStackTraceMethod {
            rva,
            code_range,
            stack_trace_hidden: hidden,
            name,
        });
    }
    if parsed != declared {
        return Err(invalid_map(
            cursor,
            "stack-trace map has fewer entries than its header declares",
        ));
    }
    methods.sort_by_key(|method: &AotStackTraceMethod| method.rva);
    Ok(AotStackTraceMap {
        status: AotStackTraceStatus::Recovered,
        methods,
        refusals,
        code_range_refusal,
    })
}

#[must_use]
pub fn recover_stack_trace_map(image: &[u8], header: &ReadyToRunHeader) -> AotStackTraceMap {
    recover(image, header)
        .unwrap_or_else(|error: crate::error::Error| AotStackTraceMap::rejected(&error))
}
