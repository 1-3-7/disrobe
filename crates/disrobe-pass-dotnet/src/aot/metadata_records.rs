use std::collections::{BTreeMap, BTreeSet, VecDeque};

use disrobe_binfmt::{Endian, NativeFile, parse_native};
use disrobe_bytes::bounded_element_capacity;
use object::read::File as ObjFile;
use serde::{Deserialize, Serialize};

use super::{
    AotSection, ReadyToRunHeader, container_address_base, decode_metadata_unsigned,
    section_bytes_for_address, section_views_agree, supported_native_format,
};

const METADATA_SECTION_ID: i32 = 313;
const METADATA_SIGNATURE: u32 = 0xDEAD_DFFD;
const SUPPORTED_MAJOR_VERSION: u16 = 10;
const SUPPORTED_MINOR_VERSION: u16 = 1;
const HANDLE_NAMESPACE_DEFINITION: u8 = 0x2f;
const HANDLE_SCOPE_DEFINITION: u8 = 0x38;
const MAX_METADATA_COLLECTION: usize = 65_536;
const MAX_METADATA_RECORDS: usize = 65_536;
const MAX_METADATA_STRING_RECORDS: usize = 131_072;
const MAX_METADATA_VALUES: usize = 1_048_576;
const MAX_METADATA_STRING_BYTES: usize = 4_096;
const MAX_METADATA_STRING_STORAGE_BYTES: usize = 16_777_216;
const MAX_METADATA_OUTPUT_BYTES: usize = 16_777_216;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotMetadataAttribution {
    pub status: AotMetadataStatus,
    pub types: Vec<AotType>,
    pub methods: Vec<AotMethod>,
}

impl AotMetadataAttribution {
    pub(crate) fn rejected(error: crate::error::Error) -> Self {
        let section_offset: Option<u32> = match &error {
            crate::error::Error::InvalidAotMetadata { offset, .. } => Some(*offset),
            _ => None,
        };
        let reason: String = error.to_string();
        Self {
            status: AotMetadataStatus::Rejected {
                section_offset,
                reason,
            },
            types: Vec::new(),
            methods: Vec::new(),
        }
    }
}

impl Default for AotMetadataAttribution {
    fn default() -> Self {
        Self {
            status: AotMetadataStatus::NotPresent,
            types: Vec::new(),
            methods: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AotMetadataStatus {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotType {
    pub record_offset: u32,
    pub namespace: Option<String>,
    pub name: String,
    pub enclosing_type_record_offset: Option<u32>,
    pub method_record_offsets: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AotMethod {
    pub record_offset: u32,
    pub name: String,
}

#[derive(Debug, Clone, Copy)]
struct RawHandle {
    kind: u8,
    offset: u32,
}

struct MetadataBudget {
    values: usize,
    output_bytes: usize,
}

impl MetadataBudget {
    const fn new() -> Self {
        Self {
            values: 0,
            output_bytes: 0,
        }
    }

    fn claim_values(&mut self, count: usize, at: usize) -> crate::error::Result<()> {
        let values: usize = self
            .values
            .checked_add(count)
            .ok_or_else(|| invalid_metadata(at, "metadata value count overflowed"))?;
        if values > MAX_METADATA_VALUES {
            return Err(invalid_metadata(
                at,
                "metadata value count exceeds parser limit",
            ));
        }
        self.values = values;
        Ok(())
    }

    fn claim_output(&mut self, count: usize, at: usize) -> crate::error::Result<()> {
        let output_bytes: usize = self
            .output_bytes
            .checked_add(count)
            .ok_or_else(|| invalid_metadata(at, "metadata output size overflowed"))?;
        if output_bytes > MAX_METADATA_OUTPUT_BYTES {
            return Err(invalid_metadata(
                at,
                "metadata output size exceeds parser limit",
            ));
        }
        self.output_bytes = output_bytes;
        Ok(())
    }
}

struct MetadataCursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> MetadataCursor<'a> {
    fn new(bytes: &'a [u8], offset: u32) -> crate::error::Result<Self> {
        let at: usize = usize::try_from(offset).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(usize::MAX, "metadata record offset does not fit usize")
        })?;
        if at >= bytes.len() {
            return Err(invalid_metadata(
                at,
                "metadata record offset is outside the section",
            ));
        }
        Ok(Self { bytes, at })
    }

    fn unsigned(&mut self) -> crate::error::Result<u32> {
        let start: usize = self.at;
        let (value, width): (u32, usize) = decode_metadata_unsigned(self.bytes, self.at)
            .ok_or_else(|| invalid_metadata(start, "metadata unsigned value is malformed"))?;
        self.at = self
            .at
            .checked_add(width)
            .ok_or_else(|| invalid_metadata(start, "metadata cursor overflowed"))?;
        Ok(value)
    }

    fn typed_handle(&mut self) -> crate::error::Result<u32> {
        self.unsigned()
    }

    fn raw_handle(&mut self) -> crate::error::Result<RawHandle> {
        let start: usize = self.at;
        let value: u32 = self.unsigned()?;
        let kind_value: u32 = value & u32::from(u8::MAX);
        let kind: u8 = u8::try_from(kind_value).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(start, "metadata handle kind does not fit u8")
        })?;
        Ok(RawHandle {
            kind,
            offset: value >> 8,
        })
    }

    fn collection_count(&mut self, budget: &mut MetadataBudget) -> crate::error::Result<usize> {
        let start: usize = self.at;
        let count: u32 = self.unsigned()?;
        let count: usize = usize::try_from(count).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(start, "metadata collection count does not fit usize")
        })?;
        if count > MAX_METADATA_COLLECTION {
            return Err(invalid_metadata(
                start,
                "metadata collection count exceeds parser limit",
            ));
        }
        let remaining: usize = self
            .bytes
            .len()
            .checked_sub(self.at)
            .ok_or_else(|| invalid_metadata(start, "metadata cursor exceeds the section"))?;
        let capacity: usize = bounded_element_capacity(
            u64::try_from(count).map_err(|_: std::num::TryFromIntError| {
                invalid_metadata(start, "metadata collection count does not fit u64")
            })?,
            1,
            remaining,
        )
        .min(count);
        if capacity != count || count > remaining {
            return Err(invalid_metadata(
                start,
                "metadata collection count exceeds the remaining bytes",
            ));
        }
        budget.claim_values(count, start)?;
        Ok(count)
    }

    fn typed_collection(&mut self, budget: &mut MetadataBudget) -> crate::error::Result<Vec<u32>> {
        let count: usize = self.collection_count(budget)?;
        let mut values: Vec<u32> = Vec::with_capacity(count);
        for _ in 0..count {
            let value: u32 = self.typed_handle()?;
            values.push(value);
        }
        Ok(values)
    }

    fn skip_typed_collection(&mut self, budget: &mut MetadataBudget) -> crate::error::Result<()> {
        let count: usize = self.collection_count(budget)?;
        for _ in 0..count {
            let _value: u32 = self.typed_handle()?;
        }
        Ok(())
    }

    fn skip_raw_collection(&mut self, budget: &mut MetadataBudget) -> crate::error::Result<()> {
        let count: usize = self.collection_count(budget)?;
        for _ in 0..count {
            let _value: RawHandle = self.raw_handle()?;
        }
        Ok(())
    }

    fn skip_bytes(&mut self) -> crate::error::Result<()> {
        let start: usize = self.at;
        let count: u32 = self.unsigned()?;
        let count: usize = usize::try_from(count).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(start, "metadata byte count does not fit usize")
        })?;
        self.at = self
            .at
            .checked_add(count)
            .filter(|end: &usize| *end <= self.bytes.len())
            .ok_or_else(|| {
                invalid_metadata(start, "metadata byte collection exceeds the section")
            })?;
        Ok(())
    }
}

struct ScopeRecord {
    offset: u32,
    root_namespace: u32,
    end: usize,
}

struct NamespaceRecord {
    offset: u32,
    parent: RawHandle,
    name: String,
    types: Vec<u32>,
    children: Vec<u32>,
    end: usize,
}

struct TypeRecord {
    offset: u32,
    namespace: u32,
    name: String,
    enclosing_type: u32,
    nested_types: Vec<u32>,
    methods: Vec<u32>,
    end: usize,
}

struct MethodRecord {
    offset: u32,
    name: String,
    end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordRange {
    start: usize,
    end: usize,
}

struct MetadataStrings {
    records: BTreeMap<u32, MetadataStringRecord>,
    stored_bytes: usize,
}

struct MetadataStringRecord {
    range: RecordRange,
    value: String,
}

impl MetadataStrings {
    const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            stored_bytes: 0,
        }
    }

    fn validate(&mut self, bytes: &[u8], offset: u32) -> crate::error::Result<()> {
        if offset == 0 || self.records.contains_key(&offset) {
            return Ok(());
        }
        let at: usize = usize::try_from(offset).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(usize::MAX, "metadata string offset does not fit usize")
        })?;
        let (length, width): (u32, usize) = decode_metadata_unsigned(bytes, at)
            .ok_or_else(|| invalid_metadata(at, "metadata string length is malformed"))?;
        let length: usize = usize::try_from(length).map_err(|_: std::num::TryFromIntError| {
            invalid_metadata(at, "metadata string length does not fit usize")
        })?;
        if length > MAX_METADATA_STRING_BYTES {
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
        let value: &[u8] = bytes
            .get(start..end)
            .ok_or_else(|| invalid_metadata(at, "metadata string exceeds the section"))?;
        let value: &str = std::str::from_utf8(value).map_err(|_: std::str::Utf8Error| {
            invalid_metadata(at, "metadata string is not UTF-8")
        })?;
        if self.records.len() >= MAX_METADATA_STRING_RECORDS {
            return Err(invalid_metadata(
                at,
                "metadata string record count exceeds parser limit",
            ));
        }
        let stored_bytes: usize = self
            .stored_bytes
            .checked_add(value.len())
            .ok_or_else(|| invalid_metadata(at, "metadata string storage size overflowed"))?;
        if stored_bytes > MAX_METADATA_STRING_STORAGE_BYTES {
            return Err(invalid_metadata(
                at,
                "metadata string storage exceeds parser limit",
            ));
        }
        let record: MetadataStringRecord = MetadataStringRecord {
            range: RecordRange { start: at, end },
            value: value.to_owned(),
        };
        self.records.insert(offset, record);
        self.stored_bytes = stored_bytes;
        Ok(())
    }

    fn owned(
        &mut self,
        bytes: &[u8],
        offset: u32,
        budget: &mut MetadataBudget,
    ) -> crate::error::Result<String> {
        self.validate(bytes, offset)?;
        if offset == 0 {
            return Ok(String::new());
        }
        let at: usize = usize::try_from(offset).map_or(usize::MAX, |value: usize| value);
        let record: &MetadataStringRecord = self
            .records
            .get(&offset)
            .ok_or_else(|| invalid_metadata(at, "metadata string record is absent"))?;
        budget.claim_output(record.value.len(), at)?;
        Ok(record.value.clone())
    }
}

fn invalid_metadata(at: usize, reason: &'static str) -> crate::error::Error {
    let offset: u32 = u32::try_from(at).map_or(u32::MAX, |value: u32| value);
    crate::error::Error::InvalidAotMetadata { offset, reason }
}

fn owned_metadata_string(
    bytes: &[u8],
    offset: u32,
    budget: &mut MetadataBudget,
    strings: &mut MetadataStrings,
) -> crate::error::Result<String> {
    strings.owned(bytes, offset, budget)
}

fn parse_scope(
    bytes: &[u8],
    offset: u32,
    budget: &mut MetadataBudget,
    strings: &mut MetadataStrings,
) -> crate::error::Result<ScopeRecord> {
    let mut cursor: MetadataCursor<'_> = MetadataCursor::new(bytes, offset)?;
    let _flags: u32 = cursor.unsigned()?;
    let name_handle: u32 = cursor.typed_handle()?;
    let _hash_algorithm: u32 = cursor.unsigned()?;
    let _major: u32 = cursor.unsigned()?;
    let _minor: u32 = cursor.unsigned()?;
    let _build: u32 = cursor.unsigned()?;
    let _revision: u32 = cursor.unsigned()?;
    cursor.skip_bytes()?;
    let culture_handle: u32 = cursor.typed_handle()?;
    let root_namespace: u32 = cursor.typed_handle()?;
    let _entry_point: u32 = cursor.typed_handle()?;
    let _global_module_type: u32 = cursor.typed_handle()?;
    cursor.skip_typed_collection(budget)?;
    let module_name_handle: u32 = cursor.typed_handle()?;
    cursor.skip_bytes()?;
    cursor.skip_typed_collection(budget)?;
    strings.validate(bytes, name_handle)?;
    strings.validate(bytes, culture_handle)?;
    strings.validate(bytes, module_name_handle)?;
    if root_namespace == 0 {
        return Err(invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "scope root namespace handle is nil",
        ));
    }
    Ok(ScopeRecord {
        offset,
        root_namespace,
        end: cursor.at,
    })
}

fn parse_namespace(
    bytes: &[u8],
    offset: u32,
    budget: &mut MetadataBudget,
    strings: &mut MetadataStrings,
) -> crate::error::Result<NamespaceRecord> {
    let mut cursor: MetadataCursor<'_> = MetadataCursor::new(bytes, offset)?;
    let parent: RawHandle = cursor.raw_handle()?;
    if !matches!(
        parent.kind,
        0 | HANDLE_NAMESPACE_DEFINITION | HANDLE_SCOPE_DEFINITION
    ) {
        return Err(invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "namespace parent has an unsupported handle kind",
        ));
    }
    let name_handle: u32 = cursor.typed_handle()?;
    let types: Vec<u32> = cursor.typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    let children: Vec<u32> = cursor.typed_collection(budget)?;
    require_unique_nonzero(&types, offset, "namespace type handle is nil or duplicated")?;
    require_unique_nonzero(
        &children,
        offset,
        "namespace child handle is nil or duplicated",
    )?;
    let name: String = owned_metadata_string(bytes, name_handle, budget, strings)?;
    Ok(NamespaceRecord {
        offset,
        parent,
        name,
        types,
        children,
        end: cursor.at,
    })
}

fn parse_type(
    bytes: &[u8],
    offset: u32,
    budget: &mut MetadataBudget,
    strings: &mut MetadataStrings,
) -> crate::error::Result<TypeRecord> {
    let mut cursor: MetadataCursor<'_> = MetadataCursor::new(bytes, offset)?;
    let _flags: u32 = cursor.unsigned()?;
    let _base_type: RawHandle = cursor.raw_handle()?;
    let namespace: u32 = cursor.typed_handle()?;
    let name_handle: u32 = cursor.typed_handle()?;
    let _size: u32 = cursor.unsigned()?;
    let _packing_size: u32 = cursor.unsigned()?;
    let enclosing_type: u32 = cursor.typed_handle()?;
    let nested_types: Vec<u32> = cursor.typed_collection(budget)?;
    let methods: Vec<u32> = cursor.typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_raw_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    require_unique_nonzero(
        &nested_types,
        offset,
        "nested type handle is nil or duplicated",
    )?;
    require_unique_nonzero(&methods, offset, "method handle is nil or duplicated")?;
    let name: String = owned_metadata_string(bytes, name_handle, budget, strings)?;
    if name.is_empty() {
        return Err(invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "type name is empty",
        ));
    }
    Ok(TypeRecord {
        offset,
        namespace,
        name,
        enclosing_type,
        nested_types,
        methods,
        end: cursor.at,
    })
}

fn parse_method(
    bytes: &[u8],
    offset: u32,
    budget: &mut MetadataBudget,
    strings: &mut MetadataStrings,
) -> crate::error::Result<MethodRecord> {
    let mut cursor: MetadataCursor<'_> = MetadataCursor::new(bytes, offset)?;
    let _flags: u32 = cursor.unsigned()?;
    let _impl_flags: u32 = cursor.unsigned()?;
    let name_handle: u32 = cursor.typed_handle()?;
    let _signature: u32 = cursor.typed_handle()?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    cursor.skip_typed_collection(budget)?;
    let name: String = owned_metadata_string(bytes, name_handle, budget, strings)?;
    if name.is_empty() {
        return Err(invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "method name is empty",
        ));
    }
    Ok(MethodRecord {
        offset,
        name,
        end: cursor.at,
    })
}

fn require_unique_nonzero(
    values: &[u32],
    record_offset: u32,
    reason: &'static str,
) -> crate::error::Result<()> {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for value in values {
        if *value == 0 || !seen.insert(*value) {
            return Err(invalid_metadata(
                usize::try_from(record_offset).map_or(usize::MAX, |value: usize| value),
                reason,
            ));
        }
    }
    Ok(())
}

fn claim_record(record_count: &mut usize, offset: u32) -> crate::error::Result<()> {
    let next: usize = record_count.checked_add(1).ok_or_else(|| {
        invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "metadata record count overflowed",
        )
    })?;
    if next > MAX_METADATA_RECORDS {
        return Err(invalid_metadata(
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
            "metadata record count exceeds parser limit",
        ));
    }
    *record_count = next;
    Ok(())
}

fn validate_graph(
    scopes: &BTreeMap<u32, ScopeRecord>,
    namespaces: &BTreeMap<u32, NamespaceRecord>,
    types: &BTreeMap<u32, TypeRecord>,
    methods: &BTreeMap<u32, MethodRecord>,
    strings: &MetadataStrings,
    root_end: usize,
) -> crate::error::Result<()> {
    let mut type_owner_counts: BTreeMap<u32, u8> = BTreeMap::new();
    for namespace in namespaces.values() {
        for type_offset in &namespace.types {
            claim_type_owner(&mut type_owner_counts, *type_offset)?;
        }
    }
    for enclosing in types.values() {
        for nested_offset in &enclosing.nested_types {
            claim_type_owner(&mut type_owner_counts, *nested_offset)?;
        }
    }
    for scope in scopes.values() {
        let root_namespace: &NamespaceRecord =
            namespaces.get(&scope.root_namespace).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(scope.offset).map_or(usize::MAX, |value: usize| value),
                    "scope root namespace is not reachable",
                )
            })?;
        if root_namespace.parent.kind != HANDLE_SCOPE_DEFINITION
            || root_namespace.parent.offset != scope.offset
        {
            return Err(invalid_metadata(
                usize::try_from(root_namespace.offset).map_or(usize::MAX, |value: usize| value),
                "scope root namespace does not point back to its scope",
            ));
        }
    }
    for namespace in namespaces.values() {
        match namespace.parent.kind {
            HANDLE_NAMESPACE_DEFINITION => {
                if !namespaces.contains_key(&namespace.parent.offset) {
                    return Err(invalid_metadata(
                        usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                        "namespace parent is not reachable",
                    ));
                }
            }
            HANDLE_SCOPE_DEFINITION => {
                if !scopes.contains_key(&namespace.parent.offset) {
                    return Err(invalid_metadata(
                        usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                        "namespace scope parent is not reachable",
                    ));
                }
            }
            0 => {
                if namespace.parent.offset != 0 {
                    return Err(invalid_metadata(
                        usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                        "nil namespace parent carries an offset",
                    ));
                }
            }
            _ => {
                return Err(invalid_metadata(
                    usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                    "namespace parent kind changed after parsing",
                ));
            }
        }
        for child_offset in &namespace.children {
            let child: &NamespaceRecord = namespaces.get(child_offset).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                    "namespace child is not reachable",
                )
            })?;
            if child.parent.kind != HANDLE_NAMESPACE_DEFINITION
                || child.parent.offset != namespace.offset
            {
                return Err(invalid_metadata(
                    usize::try_from(child.offset).map_or(usize::MAX, |value: usize| value),
                    "namespace child does not point back to its parent",
                ));
            }
        }
        for type_offset in &namespace.types {
            let type_record: &TypeRecord = types.get(type_offset).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
                    "namespace type is not reachable",
                )
            })?;
            if type_record.namespace != namespace.offset {
                return Err(invalid_metadata(
                    usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                    "namespace type does not point back to its namespace",
                ));
            }
        }
    }
    let mut nested_edges: BTreeSet<(u32, u32)> = BTreeSet::new();
    for enclosing in types.values() {
        for nested_offset in &enclosing.nested_types {
            nested_edges.insert((enclosing.offset, *nested_offset));
        }
    }
    for type_record in types.values() {
        if type_owner_counts.get(&type_record.offset) != Some(&1) {
            return Err(invalid_metadata(
                usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                "type record does not have exactly one structural owner",
            ));
        }
        if type_record.namespace != 0 && !namespaces.contains_key(&type_record.namespace) {
            return Err(invalid_metadata(
                usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                "type namespace is not reachable",
            ));
        }
        if type_record.enclosing_type != 0 {
            let enclosing: &TypeRecord =
                types.get(&type_record.enclosing_type).ok_or_else(|| {
                    invalid_metadata(
                        usize::try_from(type_record.offset)
                            .map_or(usize::MAX, |value: usize| value),
                        "enclosing type is not reachable",
                    )
                })?;
            if !nested_edges.contains(&(enclosing.offset, type_record.offset)) {
                return Err(invalid_metadata(
                    usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                    "enclosing type does not contain its nested type",
                ));
            }
        }
        for nested_offset in &type_record.nested_types {
            let nested: &TypeRecord = types.get(nested_offset).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                    "nested type is not reachable",
                )
            })?;
            if nested.enclosing_type != type_record.offset {
                return Err(invalid_metadata(
                    usize::try_from(nested.offset).map_or(usize::MAX, |value: usize| value),
                    "nested type does not point back to its enclosing type",
                ));
            }
        }
        for method_offset in &type_record.methods {
            if !methods.contains_key(method_offset) {
                return Err(invalid_metadata(
                    usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                    "type method is not reachable",
                ));
            }
        }
    }
    validate_type_containment(types)?;
    validate_record_ranges(scopes, namespaces, types, methods, strings, root_end)
}

fn claim_type_owner(owners: &mut BTreeMap<u32, u8>, type_offset: u32) -> crate::error::Result<()> {
    let count: &mut u8 = owners.entry(type_offset).or_insert(0);
    *count = count.checked_add(1).ok_or_else(|| {
        invalid_metadata(
            usize::try_from(type_offset).map_or(usize::MAX, |value: usize| value),
            "type owner count overflowed",
        )
    })?;
    Ok(())
}

fn validate_type_containment(types: &BTreeMap<u32, TypeRecord>) -> crate::error::Result<()> {
    let mut states: BTreeMap<u32, u8> = BTreeMap::new();
    let mut path: Vec<u32> = Vec::with_capacity(types.len());
    for start in types.keys() {
        if states.get(start) == Some(&2) {
            continue;
        }
        path.clear();
        let mut current: u32 = *start;
        while current != 0 {
            match states.get(&current).copied() {
                Some(1) => {
                    return Err(invalid_metadata(
                        usize::try_from(current).map_or(usize::MAX, |value: usize| value),
                        "type containment graph contains a cycle",
                    ));
                }
                Some(2) => break,
                _ => {}
            }
            let type_record: &TypeRecord = types.get(&current).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(current).map_or(usize::MAX, |value: usize| value),
                    "type containment target is not reachable",
                )
            })?;
            states.insert(current, 1);
            path.push(current);
            current = type_record.enclosing_type;
        }
        for offset in &path {
            states.insert(*offset, 2);
        }
    }
    Ok(())
}

fn validate_record_ranges(
    scopes: &BTreeMap<u32, ScopeRecord>,
    namespaces: &BTreeMap<u32, NamespaceRecord>,
    types: &BTreeMap<u32, TypeRecord>,
    methods: &BTreeMap<u32, MethodRecord>,
    strings: &MetadataStrings,
    root_end: usize,
) -> crate::error::Result<()> {
    let record_count: usize = scopes
        .len()
        .checked_add(namespaces.len())
        .and_then(|value: usize| value.checked_add(types.len()))
        .and_then(|value: usize| value.checked_add(methods.len()))
        .and_then(|value: usize| value.checked_add(strings.records.len()))
        .and_then(|value: usize| value.checked_add(1))
        .ok_or_else(|| invalid_metadata(4, "metadata record range count overflowed"))?;
    let mut ranges: Vec<RecordRange> = Vec::with_capacity(record_count);
    ranges.push(RecordRange {
        start: 4,
        end: root_end,
    });
    for scope in scopes.values() {
        ranges.push(RecordRange {
            start: usize::try_from(scope.offset).map_or(usize::MAX, |value: usize| value),
            end: scope.end,
        });
    }
    for namespace in namespaces.values() {
        ranges.push(RecordRange {
            start: usize::try_from(namespace.offset).map_or(usize::MAX, |value: usize| value),
            end: namespace.end,
        });
    }
    for type_record in types.values() {
        ranges.push(RecordRange {
            start: usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
            end: type_record.end,
        });
    }
    for method in methods.values() {
        ranges.push(RecordRange {
            start: usize::try_from(method.offset).map_or(usize::MAX, |value: usize| value),
            end: method.end,
        });
    }
    for record in strings.records.values() {
        ranges.push(record.range);
    }
    ranges.sort_unstable_by_key(|range: &RecordRange| range.start);
    for range in &ranges {
        if range.start >= range.end {
            return Err(invalid_metadata(
                range.start,
                "metadata record range is empty or reversed",
            ));
        }
    }
    for pair in ranges.windows(2) {
        let previous: &RecordRange = pair
            .first()
            .ok_or_else(|| invalid_metadata(4, "metadata range pair has no first record"))?;
        let next: &RecordRange = pair
            .get(1)
            .ok_or_else(|| invalid_metadata(4, "metadata range pair has no second record"))?;
        if previous.end > next.start {
            return Err(invalid_metadata(
                next.start,
                "metadata record ranges overlap",
            ));
        }
    }
    Ok(())
}

fn namespace_qualifications(
    scopes: &BTreeMap<u32, ScopeRecord>,
    namespaces: &BTreeMap<u32, NamespaceRecord>,
    budget: &mut MetadataBudget,
) -> crate::error::Result<BTreeMap<u32, Option<String>>> {
    let mut qualifications: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    for scope in scopes.values() {
        queue.push_back(scope.root_namespace);
    }
    while let Some(offset) = queue.pop_front() {
        if qualifications.contains_key(&offset) {
            return Err(invalid_metadata(
                usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                "namespace is reachable through more than one path",
            ));
        }
        let namespace: &NamespaceRecord = namespaces.get(&offset).ok_or_else(|| {
            invalid_metadata(
                usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                "namespace qualification target is not reachable",
            )
        })?;
        let parent_name: Option<&str> = match namespace.parent.kind {
            HANDLE_NAMESPACE_DEFINITION => qualifications
                .get(&namespace.parent.offset)
                .ok_or_else(|| {
                    invalid_metadata(
                        usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                        "namespace parent qualification is absent",
                    )
                })?
                .as_deref(),
            HANDLE_SCOPE_DEFINITION | 0 => None,
            _ => {
                return Err(invalid_metadata(
                    usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                    "namespace parent kind changed during qualification",
                ));
            }
        };
        let qualified_length: usize = match (parent_name, namespace.name.as_str()) {
            (None | Some(""), name) => name.len(),
            (Some(parent), "") => parent.len(),
            (Some(parent), name) => parent
                .len()
                .checked_add(1)
                .and_then(|value: usize| value.checked_add(name.len()))
                .ok_or_else(|| {
                    invalid_metadata(
                        usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                        "namespace qualification length overflowed",
                    )
                })?,
        };
        if qualified_length > MAX_METADATA_STRING_BYTES {
            return Err(invalid_metadata(
                usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
                "namespace qualification exceeds parser limit",
            ));
        }
        budget.claim_output(
            qualified_length,
            usize::try_from(offset).map_or(usize::MAX, |value: usize| value),
        )?;
        let qualified: Option<String> = match (parent_name, namespace.name.as_str()) {
            (None | Some(""), "") => None,
            (None | Some(""), name) => Some(name.to_owned()),
            (Some(parent), "") => Some(parent.to_owned()),
            (Some(parent), name) => {
                let mut value: String = String::with_capacity(qualified_length);
                value.push_str(parent);
                value.push('.');
                value.push_str(name);
                Some(value)
            }
        };
        for child_offset in &namespace.children {
            queue.push_back(*child_offset);
        }
        qualifications.insert(offset, qualified);
    }
    if qualifications.len() != namespaces.len() {
        return Err(invalid_metadata(
            4,
            "not every namespace is reachable from a scope root",
        ));
    }
    Ok(qualifications)
}

fn type_namespace_qualifications(
    types: &BTreeMap<u32, TypeRecord>,
    namespaces: &BTreeMap<u32, Option<String>>,
    budget: &mut MetadataBudget,
) -> crate::error::Result<BTreeMap<u32, Option<String>>> {
    let mut qualifications: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut path: Vec<u32> = Vec::with_capacity(types.len());
    for start in types.keys() {
        if qualifications.contains_key(start) {
            continue;
        }
        path.clear();
        let mut current: u32 = *start;
        let inherited: Option<String> = loop {
            if let Some(existing) = qualifications.get(&current) {
                break existing.clone();
            }
            let type_record: &TypeRecord = types.get(&current).ok_or_else(|| {
                invalid_metadata(
                    usize::try_from(current).map_or(usize::MAX, |value: usize| value),
                    "type namespace path is not reachable",
                )
            })?;
            path.push(current);
            if type_record.namespace != 0 {
                let value: &Option<String> =
                    namespaces.get(&type_record.namespace).ok_or_else(|| {
                        invalid_metadata(
                            usize::try_from(current).map_or(usize::MAX, |value: usize| value),
                            "type namespace qualification is absent",
                        )
                    })?;
                break value.clone();
            }
            if type_record.enclosing_type == 0 {
                break None;
            }
            current = type_record.enclosing_type;
        };
        for offset in path.iter().rev() {
            let value_length: usize = inherited.as_ref().map_or(0, |value: &String| value.len());
            budget.claim_output(
                value_length,
                usize::try_from(*offset).map_or(usize::MAX, |value: usize| value),
            )?;
            qualifications.insert(*offset, inherited.clone());
        }
    }
    if qualifications.len() != types.len() {
        return Err(invalid_metadata(
            4,
            "not every type has a namespace resolution",
        ));
    }
    Ok(qualifications)
}

fn parse_metadata_records(bytes: &[u8]) -> crate::error::Result<(Vec<AotType>, Vec<AotMethod>)> {
    let signature_bytes: &[u8] = bytes
        .get(0..4)
        .ok_or_else(|| invalid_metadata(0, "metadata signature is truncated"))?;
    let signature: [u8; 4] =
        <[u8; 4]>::try_from(signature_bytes).map_err(|_: std::array::TryFromSliceError| {
            invalid_metadata(0, "metadata signature is truncated")
        })?;
    if u32::from_le_bytes(signature) != METADATA_SIGNATURE {
        return Err(invalid_metadata(0, "metadata signature does not match"));
    }
    let mut budget: MetadataBudget = MetadataBudget::new();
    let mut strings: MetadataStrings = MetadataStrings::new();
    let mut root: MetadataCursor<'_> = MetadataCursor::new(bytes, 4)?;
    let scope_offsets: Vec<u32> = root.typed_collection(&mut budget)?;
    require_unique_nonzero(&scope_offsets, 4, "scope handle is nil or duplicated")?;
    let root_end: usize = root.at;
    let mut record_count: usize = 0;
    let mut scopes: BTreeMap<u32, ScopeRecord> = BTreeMap::new();
    let mut namespace_queue: VecDeque<u32> = VecDeque::new();
    for scope_offset in scope_offsets {
        claim_record(&mut record_count, scope_offset)?;
        let scope: ScopeRecord = parse_scope(bytes, scope_offset, &mut budget, &mut strings)?;
        namespace_queue.push_back(scope.root_namespace);
        if scopes.insert(scope.offset, scope).is_some() {
            return Err(invalid_metadata(
                usize::try_from(scope_offset).map_or(usize::MAX, |value: usize| value),
                "scope record is duplicated",
            ));
        }
    }
    let mut namespaces: BTreeMap<u32, NamespaceRecord> = BTreeMap::new();
    let mut type_queue: VecDeque<u32> = VecDeque::new();
    while let Some(offset) = namespace_queue.pop_front() {
        if namespaces.contains_key(&offset) {
            continue;
        }
        claim_record(&mut record_count, offset)?;
        let namespace: NamespaceRecord = parse_namespace(bytes, offset, &mut budget, &mut strings)?;
        for type_offset in &namespace.types {
            type_queue.push_back(*type_offset);
        }
        for child_offset in &namespace.children {
            namespace_queue.push_back(*child_offset);
        }
        namespaces.insert(offset, namespace);
    }
    let mut types: BTreeMap<u32, TypeRecord> = BTreeMap::new();
    let mut method_offsets: BTreeSet<u32> = BTreeSet::new();
    while let Some(offset) = type_queue.pop_front() {
        if types.contains_key(&offset) {
            continue;
        }
        claim_record(&mut record_count, offset)?;
        let type_record: TypeRecord = parse_type(bytes, offset, &mut budget, &mut strings)?;
        for nested_offset in &type_record.nested_types {
            type_queue.push_back(*nested_offset);
        }
        for method_offset in &type_record.methods {
            method_offsets.insert(*method_offset);
        }
        types.insert(offset, type_record);
    }
    let mut methods: BTreeMap<u32, MethodRecord> = BTreeMap::new();
    for method_offset in method_offsets {
        claim_record(&mut record_count, method_offset)?;
        let method: MethodRecord = parse_method(bytes, method_offset, &mut budget, &mut strings)?;
        methods.insert(method_offset, method);
    }
    validate_graph(&scopes, &namespaces, &types, &methods, &strings, root_end)?;
    let qualifications: BTreeMap<u32, Option<String>> =
        namespace_qualifications(&scopes, &namespaces, &mut budget)?;
    let mut type_qualifications: BTreeMap<u32, Option<String>> =
        type_namespace_qualifications(&types, &qualifications, &mut budget)?;
    let type_capacity: usize = types.len();
    let mut attributed_types: Vec<AotType> = Vec::with_capacity(type_capacity);
    for (_, type_record) in types {
        let Some(namespace): Option<Option<String>> =
            type_qualifications.remove(&type_record.offset)
        else {
            return Err(invalid_metadata(
                usize::try_from(type_record.offset).map_or(usize::MAX, |value: usize| value),
                "type namespace resolution is absent",
            ));
        };
        attributed_types.push(AotType {
            record_offset: type_record.offset,
            namespace,
            name: type_record.name,
            enclosing_type_record_offset: (type_record.enclosing_type != 0)
                .then_some(type_record.enclosing_type),
            method_record_offsets: type_record.methods,
        });
    }
    let method_capacity: usize = methods.len();
    let mut attributed_methods: Vec<AotMethod> = Vec::with_capacity(method_capacity);
    for (_, method) in methods {
        attributed_methods.push(AotMethod {
            record_offset: method.offset,
            name: method.name,
        });
    }
    Ok((attributed_types, attributed_methods))
}

fn metadata_section(header: &ReadyToRunHeader) -> crate::error::Result<Option<&AotSection>> {
    let mut found: Option<&AotSection> = None;
    for section in &header.sections {
        if section.id != METADATA_SECTION_ID {
            continue;
        }
        if found.is_some() {
            return Err(invalid_metadata(
                0,
                "metadata section appears more than once",
            ));
        }
        found = Some(section);
    }
    Ok(found)
}

fn metadata_section_bytes<'a>(
    image: &'a [u8],
    section: &AotSection,
) -> crate::error::Result<&'a [u8]> {
    let native: NativeFile = parse_native(image).map_err(|error: disrobe_binfmt::Error| {
        crate::error::Error::AotContainerRead(error.to_string())
    })?;
    if !supported_native_format(native.format) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            native.format.label(),
        ));
    }
    if !matches!(native.endian, Endian::Little) {
        return Err(crate::error::Error::UnsupportedAotContainer(
            "big-endian image",
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
    let start: u64 = address_base
        .checked_add(u64::from(section.start_rva))
        .ok_or_else(|| {
            crate::error::Error::AotContainerRead(
                "metadata section start address overflowed".to_owned(),
            )
        })?;
    let end: u64 = address_base
        .checked_add(u64::from(section.end_rva))
        .ok_or_else(|| {
            crate::error::Error::AotContainerRead(
                "metadata section end address overflowed".to_owned(),
            )
        })?;
    section_bytes_for_address(image, &file, start, end).ok_or_else(|| {
        crate::error::Error::AotContainerRead(
            "metadata section is not entirely file backed".to_owned(),
        )
    })
}

pub fn recover_metadata_attribution(
    image: &[u8],
    header: &ReadyToRunHeader,
) -> crate::error::Result<AotMetadataAttribution> {
    let Some(section): Option<&AotSection> = metadata_section(header)? else {
        return Ok(AotMetadataAttribution::default());
    };
    if header.major_version != SUPPORTED_MAJOR_VERSION
        || header.minor_version != SUPPORTED_MINOR_VERSION
    {
        return Ok(AotMetadataAttribution {
            status: AotMetadataStatus::UnsupportedVersion {
                major_version: header.major_version,
                minor_version: header.minor_version,
            },
            types: Vec::new(),
            methods: Vec::new(),
        });
    }
    let bytes: &[u8] = metadata_section_bytes(image, section)?;
    let (types, methods): (Vec<AotType>, Vec<AotMethod>) = parse_metadata_records(bytes)?;
    Ok(AotMetadataAttribution {
        status: AotMetadataStatus::Recovered,
        types,
        methods,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        MetadataStrings, MethodRecord, NamespaceRecord, ScopeRecord, TypeRecord,
        validate_record_ranges, validate_type_containment,
    };

    fn type_record(offset: u32, enclosing_type: u32, nested_types: Vec<u32>) -> TypeRecord {
        TypeRecord {
            offset,
            namespace: 0,
            name: format!("Type{offset}"),
            enclosing_type,
            nested_types,
            methods: Vec::new(),
            end: usize::try_from(offset).map_or(usize::MAX, |value: usize| value.saturating_add(1)),
        }
    }

    #[test]
    fn type_containment_cycles_are_rejected() {
        let mut types: BTreeMap<u32, TypeRecord> = BTreeMap::new();
        types.insert(10, type_record(10, 20, vec![20]));
        types.insert(20, type_record(20, 10, vec![10]));
        let result: crate::error::Result<()> = validate_type_containment(&types);
        assert!(matches!(
            result,
            Err(crate::error::Error::InvalidAotMetadata { .. })
        ));
    }

    #[test]
    fn acyclic_type_containment_is_accepted() {
        let mut types: BTreeMap<u32, TypeRecord> = BTreeMap::new();
        types.insert(10, type_record(10, 0, vec![20]));
        types.insert(20, type_record(20, 10, Vec::new()));
        let result: crate::error::Result<()> = validate_type_containment(&types);
        assert!(result.is_ok());
    }

    #[test]
    fn string_records_cannot_alias_structural_records() {
        let mut bytes: Vec<u8> = vec![0; 16];
        bytes[5..8].copy_from_slice(&[4, b'A', b'B']);
        let mut strings: MetadataStrings = MetadataStrings::new();
        let first: crate::error::Result<()> = strings.validate(&bytes, 5);
        let second: crate::error::Result<()> = strings.validate(&bytes, 5);
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(strings.records.len(), 1);
        let scopes: BTreeMap<u32, ScopeRecord> = BTreeMap::new();
        let namespaces: BTreeMap<u32, NamespaceRecord> = BTreeMap::new();
        let types: BTreeMap<u32, TypeRecord> = BTreeMap::new();
        let methods: BTreeMap<u32, MethodRecord> = BTreeMap::new();
        let result: crate::error::Result<()> =
            validate_record_ranges(&scopes, &namespaces, &types, &methods, &strings, 8);
        assert!(matches!(
            result,
            Err(crate::error::Error::InvalidAotMetadata { .. })
        ));
    }
}
