#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::mem::size_of;

use crate::dalvik_to_jvm::{EmittedCode, emit_branch_method_code, emit_method_code};
use crate::dex::{CodeItem, DexFile, parse_code_items};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

const ACC_INTERFACE: u16 = 0x0200;
const ACC_ABSTRACT: u16 = 0x0400;
const ACC_NATIVE: u16 = 0x0100;
const ACC_STATIC: u16 = 0x0008;
const ACC_SUPER: u16 = 0x0020;
const CLASS_VERSION_MAJOR: u16 = 52;
const CLASS_VERSION_MINOR: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedMethod {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    pub has_code: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedField {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslatedClass {
    pub internal_name: String,
    pub super_name: String,
    pub interfaces: Vec<String>,
    pub access_flags: u16,
    pub fields: Vec<TranslatedField>,
    pub methods: Vec<TranslatedMethod>,
}

impl TranslatedClass {
    #[inline]
    #[must_use]
    pub const fn is_interface(&self) -> bool {
        self.access_flags & ACC_INTERFACE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dex2JarResult {
    pub classes: Vec<TranslatedClass>,
    pub jar_entries: BTreeMap<String, Vec<u8>>,
    pub method_total: usize,
    pub bodies_recovered: usize,
    pub stubbed_body_count: usize,
    #[serde(default)]
    pub code_scan_complete: bool,
    #[serde(default)]
    pub decode_error_count: usize,
    #[serde(default)]
    pub diagnostics: Vec<Dex2JarDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dex2JarDiagnostic {
    pub class: String,
    pub method: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dex2JarLimits {
    pub input_bytes: usize,
    pub classes: usize,
    pub class_bytes: usize,
    pub jar_bytes: usize,
}

impl Default for Dex2JarLimits {
    fn default() -> Self {
        Self {
            input_bytes: 64 * 1024 * 1024,
            classes: 65_536,
            class_bytes: 128 * 1024 * 1024,
            jar_bytes: 128 * 1024 * 1024,
        }
    }
}

struct AllocationBudget {
    spent: usize,
    limit: usize,
}

impl AllocationBudget {
    const fn new(limit: usize) -> Self {
        Self { spent: 0, limit }
    }

    const fn claim(&mut self, bytes: usize) -> Result<()> {
        let actual: usize = self.spent.saturating_add(bytes);
        if actual > self.limit {
            return Err(Error::Dex2JarLimit {
                kind: "DEX translation allocation",
                actual,
                limit: self.limit,
            });
        }
        self.spent = actual;
        Ok(())
    }

    fn vector<T>(&mut self, count: usize) -> Result<Vec<T>> {
        let bytes: usize = count.saturating_mul(size_of::<T>());
        self.claim(bytes)?;
        let mut out: Vec<T> = Vec::new();
        out.try_reserve_exact(count)
            .map_err(|_| Error::Dex2JarLimit {
                kind: "DEX translation allocation",
                actual: usize::MAX,
                limit: self.limit,
            })?;
        Ok(out)
    }

    fn string(&mut self, value: &str) -> Result<String> {
        self.claim(value.len())?;
        let mut out: String = String::new();
        out.try_reserve_exact(value.len())
            .map_err(|_| Error::Dex2JarLimit {
                kind: "DEX translation allocation",
                actual: usize::MAX,
                limit: self.limit,
            })?;
        out.push_str(value);
        Ok(out)
    }
}

const fn translation_allocation_limit(limits: Dex2JarLimits) -> usize {
    limits.input_bytes.saturating_mul(8)
}

fn validate_preparse_limits(
    header: &crate::dex::DexHeader,
    dex_bytes: &[u8],
    limits: Dex2JarLimits,
) -> Result<()> {
    if dex_bytes.len() > limits.input_bytes {
        return Err(Error::Dex2JarLimit {
            kind: "input bytes",
            actual: dex_bytes.len(),
            limit: limits.input_bytes,
        });
    }
    let classes: usize = usize::try_from(header.class_defs_size).unwrap_or(usize::MAX);
    if classes > limits.classes {
        return Err(Error::Dex2JarLimit {
            kind: "class count",
            actual: classes,
            limit: limits.classes,
        });
    }
    let table_bytes: usize = [
        (header.string_ids_size, 4_usize),
        (header.type_ids_size, 4),
        (header.proto_ids_size, 12),
        (header.field_ids_size, 8),
        (header.method_ids_size, 8),
        (header.class_defs_size, 32),
    ]
    .into_iter()
    .try_fold(0_usize, |total: usize, (count, width): (u32, usize)| {
        total.checked_add(usize::try_from(count).ok()?.checked_mul(width)?)
    })
    .unwrap_or(usize::MAX);
    if table_bytes > dex_bytes.len() {
        return Err(Error::Dex2JarLimit {
            kind: "DEX table bytes",
            actual: table_bytes,
            limit: dex_bytes.len(),
        });
    }
    let members: usize = usize::try_from(header.field_ids_size)
        .unwrap_or(usize::MAX)
        .saturating_add(usize::try_from(header.method_ids_size).unwrap_or(usize::MAX));
    let member_limit: usize = limits.input_bytes / 8;
    if members > member_limit {
        return Err(Error::Dex2JarLimit {
            kind: "DEX members",
            actual: members,
            limit: member_limit,
        });
    }
    let table_allocation: usize = [
        (
            usize::try_from(header.string_ids_size).unwrap_or(usize::MAX),
            size_of::<String>(),
        ),
        (
            usize::try_from(header.type_ids_size).unwrap_or(usize::MAX),
            size_of::<String>(),
        ),
        (
            usize::try_from(header.proto_ids_size).unwrap_or(usize::MAX),
            size_of::<crate::dex::ProtoId>(),
        ),
        (
            usize::try_from(header.field_ids_size).unwrap_or(usize::MAX),
            size_of::<crate::dex::FieldId>(),
        ),
        (
            usize::try_from(header.method_ids_size).unwrap_or(usize::MAX),
            size_of::<crate::dex::MethodId>(),
        ),
        (
            usize::try_from(header.class_defs_size).unwrap_or(usize::MAX),
            size_of::<String>(),
        ),
    ]
    .into_iter()
    .try_fold(0_usize, |total: usize, (count, width): (usize, usize)| {
        total.checked_add(count.checked_mul(width)?)
    })
    .unwrap_or(usize::MAX);
    let allocation_limit: usize = translation_allocation_limit(limits);
    if table_allocation > allocation_limit {
        return Err(Error::Dex2JarLimit {
            kind: "DEX parse allocation",
            actual: table_allocation,
            limit: allocation_limit,
        });
    }
    let amplified_allocation: usize = preparse_amplified_allocation(header, dex_bytes)?;
    if amplified_allocation > allocation_limit {
        return Err(Error::Dex2JarLimit {
            kind: "DEX parse allocation",
            actual: amplified_allocation,
            limit: allocation_limit,
        });
    }
    Ok(())
}

fn preparse_table_entry(bytes: &[u8], base: u32, index: usize, width: usize) -> Option<usize> {
    let offset: usize = usize::try_from(base)
        .ok()?
        .checked_add(index.checked_mul(width)?)?;
    let end: usize = offset.checked_add(width)?;
    (end <= bytes.len()).then_some(offset)
}

fn preparse_string_lengths(header: &crate::dex::DexHeader, bytes: &[u8]) -> Result<Vec<usize>> {
    let count: usize = usize::try_from(header.string_ids_size).unwrap_or(usize::MAX);
    let mut lengths: Vec<usize> = Vec::new();
    lengths
        .try_reserve_exact(count)
        .map_err(|_| Error::Dex2JarLimit {
            kind: "DEX parse allocation",
            actual: usize::MAX,
            limit: bytes.len().saturating_mul(8),
        })?;
    let mut scanned: BTreeMap<usize, usize> = BTreeMap::new();
    for index in 0..count {
        let entry: usize = preparse_table_entry(bytes, header.string_ids_off, index, 4)
            .ok_or_else(|| malformed("parsed DEX", "string identifier table is truncated"))?;
        let data_offset: usize = usize::try_from(
            read_u32(bytes, entry)
                .ok_or_else(|| malformed("parsed DEX", "string identifier is truncated"))?,
        )
        .unwrap_or(usize::MAX);
        let raw_length: usize = if let Some(length) = scanned.get(&data_offset) {
            *length
        } else {
            let (_, start): (u32, usize) = crate::dex::read_uleb128(bytes, data_offset)
                .map_err(|_| malformed("parsed DEX", "string data is truncated"))?;
            let length: usize = bytes
                .get(start..)
                .and_then(|tail: &[u8]| tail.iter().position(|byte: &u8| *byte == 0))
                .ok_or_else(|| malformed("parsed DEX", "string data is not terminated"))?;
            scanned.insert(data_offset, length);
            length
        };
        lengths.push(raw_length);
    }
    Ok(lengths)
}

fn preparse_type_lengths(
    header: &crate::dex::DexHeader,
    bytes: &[u8],
    string_lengths: &[usize],
) -> Result<Vec<usize>> {
    let count: usize = usize::try_from(header.type_ids_size).unwrap_or(usize::MAX);
    let mut lengths: Vec<usize> = Vec::new();
    lengths
        .try_reserve_exact(count)
        .map_err(|_| Error::Dex2JarLimit {
            kind: "DEX parse allocation",
            actual: usize::MAX,
            limit: bytes.len().saturating_mul(8),
        })?;
    for index in 0..count {
        let entry: usize = preparse_table_entry(bytes, header.type_ids_off, index, 4)
            .ok_or_else(|| malformed("parsed DEX", "type identifier table is truncated"))?;
        let string_index: usize = usize::try_from(
            read_u32(bytes, entry)
                .ok_or_else(|| malformed("parsed DEX", "type identifier is truncated"))?,
        )
        .unwrap_or(usize::MAX);
        lengths.push(*string_lengths.get(string_index).ok_or_else(|| {
            malformed("parsed DEX", "type descriptor string index is out of range")
        })?);
    }
    Ok(lengths)
}

#[derive(Clone, Copy)]
struct PreparseProtoAllocation {
    string_bytes: usize,
    parameter_count: usize,
}

fn preparse_proto_allocations(
    header: &crate::dex::DexHeader,
    bytes: &[u8],
    string_lengths: &[usize],
    type_lengths: &[usize],
) -> Result<Vec<PreparseProtoAllocation>> {
    let count: usize = usize::try_from(header.proto_ids_size).unwrap_or(usize::MAX);
    let mut allocations: Vec<PreparseProtoAllocation> = Vec::new();
    allocations
        .try_reserve_exact(count)
        .map_err(|_| Error::Dex2JarLimit {
            kind: "DEX parse allocation",
            actual: usize::MAX,
            limit: bytes.len().saturating_mul(8),
        })?;
    for index in 0..count {
        let entry: usize = preparse_table_entry(bytes, header.proto_ids_off, index, 12)
            .ok_or_else(|| malformed("parsed DEX", "prototype identifier table is truncated"))?;
        let shorty_index: usize = read_u32(bytes, entry).unwrap_or(u32::MAX) as usize;
        let return_index: usize = read_u32(bytes, entry + 4).unwrap_or(u32::MAX) as usize;
        let parameters_offset: usize = read_u32(bytes, entry + 8).unwrap_or(u32::MAX) as usize;
        let mut string_bytes: usize = string_lengths
            .get(shorty_index)
            .copied()
            .and_then(|length: usize| length.checked_add(*type_lengths.get(return_index)?))
            .ok_or_else(|| malformed("parsed DEX", "prototype index is out of range"))?;
        let parameter_count: usize =
            if parameters_offset == 0 {
                0
            } else {
                usize::try_from(read_u32(bytes, parameters_offset).ok_or_else(|| {
                    malformed("parsed DEX", "prototype parameter list is truncated")
                })?)
                .unwrap_or(usize::MAX)
            };
        for parameter in 0..parameter_count {
            let offset: usize = parameters_offset
                .checked_add(4)
                .and_then(|start: usize| start.checked_add(parameter.checked_mul(2)?))
                .ok_or_else(|| malformed("parsed DEX", "prototype parameter offset overflows"))?;
            let bytes_pair: &[u8] = bytes
                .get(offset..offset.saturating_add(2))
                .ok_or_else(|| malformed("parsed DEX", "prototype parameter list is truncated"))?;
            let type_index: usize = usize::from(u16::from_le_bytes([bytes_pair[0], bytes_pair[1]]));
            string_bytes = string_bytes
                .checked_add(*type_lengths.get(type_index).ok_or_else(|| {
                    malformed(
                        "parsed DEX",
                        "prototype parameter type index is out of range",
                    )
                })?)
                .ok_or_else(|| malformed("parsed DEX", "prototype allocation overflows"))?;
        }
        allocations.push(PreparseProtoAllocation {
            string_bytes,
            parameter_count,
        });
    }
    Ok(allocations)
}

fn preparse_amplified_allocation(header: &crate::dex::DexHeader, bytes: &[u8]) -> Result<usize> {
    let string_lengths: Vec<usize> = preparse_string_lengths(header, bytes)?;
    let type_lengths: Vec<usize> = preparse_type_lengths(header, bytes, &string_lengths)?;
    let prototypes: Vec<PreparseProtoAllocation> =
        preparse_proto_allocations(header, bytes, &string_lengths, &type_lengths)?;
    let mut allocation: usize = string_lengths
        .iter()
        .chain(type_lengths.iter())
        .try_fold(0_usize, |total: usize, length: &usize| {
            total.checked_add(*length)
        })
        .unwrap_or(usize::MAX);
    for prototype in &prototypes {
        allocation = allocation
            .checked_add(size_of::<crate::dex::ProtoId>())
            .and_then(|total: usize| total.checked_add(prototype.string_bytes))
            .and_then(|total: usize| {
                total.checked_add(prototype.parameter_count.checked_mul(size_of::<String>())?)
            })
            .unwrap_or(usize::MAX);
    }
    let class_count: usize = usize::try_from(header.class_defs_size).unwrap_or(usize::MAX);
    for index in 0..class_count {
        let entry: usize = preparse_table_entry(bytes, header.class_defs_off, index, 32)
            .ok_or_else(|| malformed("parsed DEX", "class definition table is truncated"))?;
        let class_index: usize = read_u32(bytes, entry).unwrap_or(u32::MAX) as usize;
        let superclass_index: u32 = read_u32(bytes, entry + 8).unwrap_or(u32::MAX);
        let class_bytes: usize = *type_lengths
            .get(class_index)
            .ok_or_else(|| malformed("parsed DEX", "class type index is out of range"))?;
        allocation = allocation.saturating_add(class_bytes);
        if superclass_index != crate::dex::DEX_NO_INDEX {
            let superclass_bytes: usize = *type_lengths
                .get(superclass_index as usize)
                .ok_or_else(|| malformed("parsed DEX", "superclass type index is out of range"))?;
            allocation = allocation
                .checked_add(class_bytes)
                .and_then(|total: usize| total.checked_add(superclass_bytes))
                .unwrap_or(usize::MAX);
        }
    }
    let field_count: usize = usize::try_from(header.field_ids_size).unwrap_or(usize::MAX);
    for index in 0..field_count {
        let entry: usize = preparse_table_entry(bytes, header.field_ids_off, index, 8)
            .ok_or_else(|| malformed("parsed DEX", "field identifier table is truncated"))?;
        let class_index: usize = usize::from(
            bytes
                .get(entry..entry + 2)
                .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
                .ok_or_else(|| malformed("parsed DEX", "field identifier is truncated"))?,
        );
        let type_index: usize = usize::from(
            bytes
                .get(entry + 2..entry + 4)
                .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
                .ok_or_else(|| malformed("parsed DEX", "field identifier is truncated"))?,
        );
        let name_index: usize = read_u32(bytes, entry + 4).unwrap_or(u32::MAX) as usize;
        let class_bytes: usize = *type_lengths
            .get(class_index)
            .ok_or_else(|| malformed("parsed DEX", "field class index is out of range"))?;
        let type_bytes: usize = *type_lengths
            .get(type_index)
            .ok_or_else(|| malformed("parsed DEX", "field type index is out of range"))?;
        let name_bytes: usize = *string_lengths
            .get(name_index)
            .ok_or_else(|| malformed("parsed DEX", "field name index is out of range"))?;
        allocation = allocation
            .checked_add(class_bytes)
            .and_then(|total: usize| total.checked_add(type_bytes))
            .and_then(|total: usize| total.checked_add(name_bytes))
            .unwrap_or(usize::MAX);
    }
    let method_count: usize = usize::try_from(header.method_ids_size).unwrap_or(usize::MAX);
    for index in 0..method_count {
        let entry: usize = preparse_table_entry(bytes, header.method_ids_off, index, 8)
            .ok_or_else(|| malformed("parsed DEX", "method identifier table is truncated"))?;
        let class_index: usize = usize::from(
            bytes
                .get(entry..entry + 2)
                .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
                .ok_or_else(|| malformed("parsed DEX", "method identifier is truncated"))?,
        );
        let proto_index: usize = usize::from(
            bytes
                .get(entry + 2..entry + 4)
                .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
                .ok_or_else(|| malformed("parsed DEX", "method identifier is truncated"))?,
        );
        let name_index: usize = read_u32(bytes, entry + 4).unwrap_or(u32::MAX) as usize;
        let prototype: PreparseProtoAllocation = *prototypes
            .get(proto_index)
            .ok_or_else(|| malformed("parsed DEX", "method prototype index is out of range"))?;
        allocation = allocation
            .checked_add(size_of::<crate::dex::MethodId>())
            .and_then(|total: usize| total.checked_add(*type_lengths.get(class_index)?))
            .and_then(|total: usize| total.checked_add(*string_lengths.get(name_index)?))
            .and_then(|total: usize| total.checked_add(prototype.string_bytes))
            .and_then(|total: usize| {
                total.checked_add(prototype.parameter_count.checked_mul(size_of::<String>())?)
            })
            .unwrap_or(usize::MAX);
    }
    Ok(allocation)
}

fn validate_parsed_tables(dex: &DexFile) -> Result<()> {
    let header: &crate::dex::DexHeader = &dex.header;
    for (actual, declared, reason) in [
        (
            dex.strings.len(),
            header.string_ids_size,
            "parsed string table does not match the DEX header",
        ),
        (
            dex.type_names.len(),
            header.type_ids_size,
            "parsed type table does not match the DEX header",
        ),
        (
            dex.proto_ids.len(),
            header.proto_ids_size,
            "parsed prototype table does not match the DEX header",
        ),
        (
            dex.field_ids.len(),
            header.field_ids_size,
            "parsed field table does not match the DEX header",
        ),
        (
            dex.method_ids.len(),
            header.method_ids_size,
            "parsed method table does not match the DEX header",
        ),
        (
            dex.class_descriptors.len(),
            header.class_defs_size,
            "parsed class table does not match the DEX header",
        ),
    ] {
        if actual != usize::try_from(declared).unwrap_or(usize::MAX) {
            return Err(malformed("parsed DEX", reason));
        }
    }
    Ok(())
}

const fn claim_string_allocation(budget: &mut AllocationBudget, value: &String) -> Result<()> {
    budget.claim(value.capacity())
}

fn claim_proto_allocation(
    budget: &mut AllocationBudget,
    prototype: &crate::dex::ProtoId,
) -> Result<()> {
    claim_string_allocation(budget, &prototype.shorty)?;
    claim_string_allocation(budget, &prototype.return_type)?;
    budget.claim(
        prototype
            .parameters
            .capacity()
            .saturating_mul(size_of::<String>()),
    )?;
    for parameter in &prototype.parameters {
        claim_string_allocation(budget, parameter)?;
    }
    Ok(())
}

fn parsed_allocation_budget(dex: &DexFile, limit: usize) -> Result<AllocationBudget> {
    let mut budget: AllocationBudget = AllocationBudget::new(limit);
    budget.claim(dex.strings.capacity().saturating_mul(size_of::<String>()))?;
    for value in &dex.strings {
        claim_string_allocation(&mut budget, value)?;
    }
    budget.claim(
        dex.type_names
            .capacity()
            .saturating_mul(size_of::<String>()),
    )?;
    for value in &dex.type_names {
        claim_string_allocation(&mut budget, value)?;
    }
    budget.claim(
        dex.class_descriptors
            .capacity()
            .saturating_mul(size_of::<String>()),
    )?;
    for value in &dex.class_descriptors {
        claim_string_allocation(&mut budget, value)?;
    }
    budget.claim(
        dex.class_super_descriptors
            .len()
            .saturating_mul(size_of::<(String, String)>()),
    )?;
    for (class, superclass) in &dex.class_super_descriptors {
        claim_string_allocation(&mut budget, class)?;
        claim_string_allocation(&mut budget, superclass)?;
    }
    budget.claim(
        dex.proto_ids
            .capacity()
            .saturating_mul(size_of::<crate::dex::ProtoId>()),
    )?;
    for prototype in &dex.proto_ids {
        claim_proto_allocation(&mut budget, prototype)?;
    }
    budget.claim(
        dex.field_ids
            .capacity()
            .saturating_mul(size_of::<crate::dex::FieldId>()),
    )?;
    for field in &dex.field_ids {
        claim_string_allocation(&mut budget, &field.class)?;
        claim_string_allocation(&mut budget, &field.type_name)?;
        claim_string_allocation(&mut budget, &field.name)?;
    }
    budget.claim(
        dex.method_ids
            .capacity()
            .saturating_mul(size_of::<crate::dex::MethodId>()),
    )?;
    for method in &dex.method_ids {
        claim_string_allocation(&mut budget, &method.class)?;
        claim_proto_allocation(&mut budget, &method.proto)?;
        claim_string_allocation(&mut budget, &method.name)?;
    }
    Ok(budget)
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    position: u64,
    logical_len: u64,
    overflowed: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let byte_count: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next: u64 = self.position.saturating_add(byte_count);
        let limit: u64 = u64::try_from(self.limit).unwrap_or(u64::MAX);
        let retained_start: usize = usize::try_from(self.position.min(limit)).unwrap_or(self.limit);
        let retained_end: usize = usize::try_from(next.min(limit)).unwrap_or(self.limit);
        if retained_end > retained_start {
            if retained_end > self.bytes.len() {
                self.bytes.resize(retained_end, 0);
            }
            self.bytes[retained_start..retained_end]
                .copy_from_slice(&bytes[..retained_end - retained_start]);
        }
        self.overflowed |= next > limit;
        self.position = next;
        self.logical_len = self.logical_len.max(next);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for LimitedWriter {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let base: i128 = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.logical_len) + i128::from(n),
        };
        let next: u64 = u64::try_from(base).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "DEX-to-JAR seek overflow")
        })?;
        self.position = next;
        Ok(next)
    }
}

#[inline]
fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)
        .map(|s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn dex_type_to_internal(descriptor: &str) -> String {
    if descriptor.starts_with('L') && descriptor.ends_with(';') {
        descriptor[1..descriptor.len() - 1].to_string()
    } else {
        descriptor.to_string()
    }
}

fn malformed(class: &str, reason: &'static str) -> Error {
    Error::MalformedDex2JarClass {
        class: class.to_owned(),
        reason,
    }
}

fn parse_type_list(
    dex_bytes: &[u8],
    off: usize,
    type_names: &[String],
    class: &str,
    budget: &mut AllocationBudget,
) -> Result<Vec<String>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let size: usize = usize::try_from(
        read_u32(dex_bytes, off)
            .ok_or_else(|| malformed(class, "interface list size is out of range"))?,
    )
    .map_err(|_| malformed(class, "interface list size does not fit this platform"))?;
    let bytes_needed: usize = size
        .checked_mul(2)
        .and_then(|value: usize| value.checked_add(4))
        .ok_or_else(|| malformed(class, "interface list size overflows"))?;
    let end: usize = off
        .checked_add(bytes_needed)
        .ok_or_else(|| malformed(class, "interface list offset overflows"))?;
    if end > dex_bytes.len() {
        return Err(malformed(class, "interface list is truncated"));
    }
    let mut out: Vec<String> = budget.vector(size)?;
    for i in 0..size {
        let entry_off: usize = off + 4 + i * 2;
        let s: &[u8] = &dex_bytes[entry_off..entry_off + 2];
        let type_idx: usize = u16::from_le_bytes([s[0], s[1]]) as usize;
        let name: &String = type_names
            .get(type_idx)
            .ok_or_else(|| malformed(class, "interface type index is out of range"))?;
        let internal: &str = if name.starts_with('L') && name.ends_with(';') {
            &name[1..name.len() - 1]
        } else {
            name
        };
        out.push(budget.string(internal)?);
    }
    Ok(out)
}

pub fn build_class_model(dex: &DexFile, dex_bytes: &[u8]) -> Result<Vec<TranslatedClass>> {
    let mut budget: AllocationBudget =
        AllocationBudget::new(translation_allocation_limit(Dex2JarLimits::default()));
    build_class_model_with_budget(dex, dex_bytes, &mut budget)
}

fn build_class_model_with_budget(
    dex: &DexFile,
    dex_bytes: &[u8],
    budget: &mut AllocationBudget,
) -> Result<Vec<TranslatedClass>> {
    let header: &crate::dex::DexHeader = &dex.header;
    let class_defs_off: usize = header.class_defs_off as usize;
    let class_count: usize = usize::try_from(header.class_defs_size).unwrap_or(usize::MAX);
    let mut classes: Vec<TranslatedClass> = budget.vector(class_count)?;
    for ci in 0..header.class_defs_size as usize {
        let base: usize = class_defs_off
            .checked_add(ci.checked_mul(32).ok_or_else(|| {
                malformed(&format!("class #{ci}"), "class definition offset overflows")
            })?)
            .ok_or_else(|| {
                malformed(&format!("class #{ci}"), "class definition offset overflows")
            })?;
        let class_label: String = format!("class #{ci}");
        let class_idx: u32 = read_u32(dex_bytes, base)
            .ok_or_else(|| malformed(&class_label, "class definition is truncated"))?;
        let access_flags: u32 = read_u32(dex_bytes, base + 4)
            .ok_or_else(|| malformed(&class_label, "class definition is truncated"))?;
        let superclass_idx: u32 = read_u32(dex_bytes, base + 8)
            .ok_or_else(|| malformed(&class_label, "class definition is truncated"))?;
        let interfaces_off: u32 = read_u32(dex_bytes, base + 12)
            .ok_or_else(|| malformed(&class_label, "class definition is truncated"))?;
        let class_data_off: u32 = read_u32(dex_bytes, base + 24)
            .ok_or_else(|| malformed(&class_label, "class definition is truncated"))?;
        let internal_descriptor: &String = dex
            .type_names
            .get(class_idx as usize)
            .ok_or_else(|| malformed(&class_label, "class type index is out of range"))?;
        let internal_name: String =
            if internal_descriptor.starts_with('L') && internal_descriptor.ends_with(';') {
                budget.string(&internal_descriptor[1..internal_descriptor.len() - 1])?
            } else {
                budget.string(internal_descriptor)?
            };
        if internal_name.is_empty() {
            return Err(malformed(&class_label, "class descriptor is empty"));
        }
        let super_name: String = if superclass_idx == 0xFFFF_FFFF {
            budget.string("java/lang/Object")?
        } else {
            let descriptor: &String =
                dex.type_names.get(superclass_idx as usize).ok_or_else(|| {
                    malformed(&internal_name, "superclass type index is out of range")
                })?;
            if descriptor.starts_with('L') && descriptor.ends_with(';') {
                budget.string(&descriptor[1..descriptor.len() - 1])?
            } else {
                budget.string(descriptor)?
            }
        };
        let interfaces: Vec<String> = parse_type_list(
            dex_bytes,
            interfaces_off as usize,
            &dex.type_names,
            &internal_name,
            budget,
        )?;
        let (fields, methods): (Vec<TranslatedField>, Vec<TranslatedMethod>) =
            if class_data_off == 0 {
                (Vec::new(), Vec::new())
            } else {
                parse_class_data(
                    dex,
                    dex_bytes,
                    class_data_off as usize,
                    &internal_name,
                    budget,
                )?
            };
        classes.push(TranslatedClass {
            internal_name,
            super_name,
            interfaces,
            access_flags: access_flags as u16,
            fields,
            methods,
        });
    }
    Ok(classes)
}

fn parse_class_data(
    dex: &DexFile,
    bytes: &[u8],
    off: usize,
    class: &str,
    budget: &mut AllocationBudget,
) -> Result<(Vec<TranslatedField>, Vec<TranslatedMethod>)> {
    let (static_fields, o1): (u32, usize) = crate::dex::read_uleb128(bytes, off)
        .map_err(|_| malformed(class, "class data is truncated"))?;
    let (instance_fields, o2): (u32, usize) = crate::dex::read_uleb128(bytes, o1)
        .map_err(|_| malformed(class, "class data is truncated"))?;
    let (direct_methods, o3): (u32, usize) = crate::dex::read_uleb128(bytes, o2)
        .map_err(|_| malformed(class, "class data is truncated"))?;
    let (virtual_methods, o4): (u32, usize) = crate::dex::read_uleb128(bytes, o3)
        .map_err(|_| malformed(class, "class data is truncated"))?;
    let field_count: usize = usize::try_from(static_fields)
        .unwrap_or(usize::MAX)
        .saturating_add(usize::try_from(instance_fields).unwrap_or(usize::MAX));
    let method_count: usize = usize::try_from(direct_methods)
        .unwrap_or(usize::MAX)
        .saturating_add(usize::try_from(virtual_methods).unwrap_or(usize::MAX));
    let mut fields: Vec<TranslatedField> = budget.vector(field_count)?;
    let mut cursor: usize = o4;
    cursor = read_encoded_fields(
        dex,
        bytes,
        cursor,
        static_fields,
        &mut fields,
        class,
        budget,
    )?;
    cursor = read_encoded_fields(
        dex,
        bytes,
        cursor,
        instance_fields,
        &mut fields,
        class,
        budget,
    )?;
    let mut methods: Vec<TranslatedMethod> = budget.vector(method_count)?;
    cursor = read_encoded_methods(
        dex,
        bytes,
        cursor,
        direct_methods,
        &mut methods,
        class,
        budget,
    )?;
    let _ = read_encoded_methods(
        dex,
        bytes,
        cursor,
        virtual_methods,
        &mut methods,
        class,
        budget,
    )?;
    Ok((fields, methods))
}

fn read_encoded_fields(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    out: &mut Vec<TranslatedField>,
    class: &str,
    budget: &mut AllocationBudget,
) -> Result<usize> {
    let mut field_idx: u32 = 0;
    for k in 0..count {
        let (idx_diff, n1): (u32, usize) = crate::dex::read_uleb128(bytes, o)
            .map_err(|_| malformed(class, "encoded field is truncated"))?;
        let (access, n2): (u32, usize) = crate::dex::read_uleb128(bytes, n1)
            .map_err(|_| malformed(class, "encoded field is truncated"))?;
        field_idx = if k == 0 {
            idx_diff
        } else {
            field_idx
                .checked_add(idx_diff)
                .ok_or_else(|| malformed(class, "encoded field index overflows"))?
        };
        let field = dex
            .field_ids
            .get(field_idx as usize)
            .ok_or_else(|| malformed(class, "encoded field index is out of range"))?;
        out.push(TranslatedField {
            name: budget.string(&field.name)?,
            descriptor: budget.string(&field.type_name)?,
            access_flags: access as u16,
        });
        o = n2;
    }
    Ok(o)
}

fn read_encoded_methods(
    dex: &DexFile,
    bytes: &[u8],
    mut o: usize,
    count: u32,
    out: &mut Vec<TranslatedMethod>,
    class: &str,
    budget: &mut AllocationBudget,
) -> Result<usize> {
    let mut method_idx: u32 = 0;
    for k in 0..count {
        let (idx_diff, n1): (u32, usize) = crate::dex::read_uleb128(bytes, o)
            .map_err(|_| malformed(class, "encoded method is truncated"))?;
        let (access, n2): (u32, usize) = crate::dex::read_uleb128(bytes, n1)
            .map_err(|_| malformed(class, "encoded method is truncated"))?;
        let (code_off, n3): (u32, usize) = crate::dex::read_uleb128(bytes, n2)
            .map_err(|_| malformed(class, "encoded method is truncated"))?;
        method_idx = if k == 0 {
            idx_diff
        } else {
            method_idx
                .checked_add(idx_diff)
                .ok_or_else(|| malformed(class, "encoded method index overflows"))?
        };
        let method = dex
            .method_ids
            .get(method_idx as usize)
            .ok_or_else(|| malformed(class, "encoded method index is out of range"))?;
        let descriptor_len: usize = method
            .proto
            .parameters
            .iter()
            .try_fold(2_usize, |length: usize, parameter: &String| {
                length.checked_add(parameter.len())
            })
            .and_then(|length: usize| length.checked_add(method.proto.return_type.len()))
            .unwrap_or(usize::MAX);
        budget.claim(descriptor_len)?;
        let mut descriptor: String = String::new();
        descriptor
            .try_reserve_exact(descriptor_len)
            .map_err(|_| Error::Dex2JarLimit {
                kind: "DEX translation allocation",
                actual: usize::MAX,
                limit: budget.limit,
            })?;
        descriptor.push('(');
        for parameter in &method.proto.parameters {
            descriptor.push_str(parameter);
        }
        descriptor.push(')');
        descriptor.push_str(&method.proto.return_type);
        out.push(TranslatedMethod {
            name: budget.string(&method.name)?,
            descriptor,
            access_flags: access as u16,
            has_code: code_off != 0,
        });
        o = n3;
    }
    Ok(o)
}

pub(crate) struct ConstantPool {
    entries: Vec<Vec<u8>>,
    utf8: BTreeMap<String, u16>,
    class: BTreeMap<String, u16>,
    name_and_type: BTreeMap<(u16, u16), u16>,
    methodref: BTreeMap<(u8, u16, u16), u16>,
    fieldref: BTreeMap<(u16, u16), u16>,
    string: BTreeMap<String, u16>,
    integer: BTreeMap<i32, u16>,
    long: BTreeMap<i64, u16>,
    float: BTreeMap<u32, u16>,
    double: BTreeMap<u64, u16>,
    byte_limit: usize,
    serialized_bytes: usize,
    refusal: Option<&'static str>,
}

impl Default for ConstantPool {
    fn default() -> Self {
        Self::with_limit(usize::MAX)
    }
}

impl ConstantPool {
    const fn with_limit(byte_limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            utf8: BTreeMap::new(),
            class: BTreeMap::new(),
            name_and_type: BTreeMap::new(),
            methodref: BTreeMap::new(),
            fieldref: BTreeMap::new(),
            string: BTreeMap::new(),
            integer: BTreeMap::new(),
            long: BTreeMap::new(),
            float: BTreeMap::new(),
            double: BTreeMap::new(),
            byte_limit,
            serialized_bytes: 2,
            refusal: None,
        }
    }

    pub(crate) fn overflowed(&self) -> bool {
        self.refusal == Some("constant pool index exceeds u16")
            || self.entries.len() >= usize::from(u16::MAX)
    }

    fn refuse(&mut self, reason: &'static str) -> u16 {
        self.refusal.get_or_insert(reason);
        0
    }

    fn next_index(&self) -> Option<u16> {
        u16::try_from(self.entries.len().checked_add(1)?).ok()
    }

    fn reserve_entry(&mut self, entry_len: usize, slots: usize) -> Option<u16> {
        if self.refusal.is_some() {
            return None;
        }
        let Some(new_slots) = self.entries.len().checked_add(slots) else {
            self.refuse("constant pool index exceeds u16");
            return None;
        };
        if new_slots >= usize::from(u16::MAX) {
            self.refuse("constant pool index exceeds u16");
            return None;
        }
        let Some(idx) = self.next_index() else {
            self.refuse("constant pool index exceeds u16");
            return None;
        };
        let actual: usize = self.serialized_bytes.saturating_add(entry_len);
        if actual > self.byte_limit {
            self.refuse("constant pool exceeds class-byte limit");
            return None;
        }
        if self.entries.try_reserve_exact(slots).is_err() {
            self.refuse("constant pool allocation failed");
            return None;
        }
        Some(idx)
    }

    fn commit_entry(&mut self, idx: u16, entry: Vec<u8>, slots: usize) -> u16 {
        self.serialized_bytes = self.serialized_bytes.saturating_add(entry.len());
        self.entries.push(entry);
        if slots == 2 {
            self.entries.push(Vec::new());
        }
        idx
    }

    fn push_bytes(&mut self, bytes: &[u8], slots: usize) -> u16 {
        let Some(idx) = self.reserve_entry(bytes.len(), slots) else {
            return 0;
        };
        let mut entry: Vec<u8> = Vec::new();
        if entry.try_reserve_exact(bytes.len()).is_err() {
            return self.refuse("constant pool allocation failed");
        }
        entry.extend_from_slice(bytes);
        self.commit_entry(idx, entry, slots)
    }

    fn check(&self, class: &str) -> Result<()> {
        if let Some(reason) = self.refusal {
            return Err(malformed(class, reason));
        }
        Ok(())
    }

    fn modified_utf8_len(s: &str) -> Option<usize> {
        s.encode_utf16()
            .try_fold(0_usize, |length: usize, unit: u16| {
                let encoded: usize = match unit {
                    0 => 2,
                    1..=0x7F => 1,
                    0x80..=0x7FF => 2,
                    _ => 3,
                };
                length.checked_add(encoded)
            })
    }

    fn encode_modified_utf8(s: &str, encoded_len: usize) -> Option<Vec<u8>> {
        let mut encoded: Vec<u8> = Vec::new();
        encoded.try_reserve_exact(encoded_len).ok()?;
        for unit in s.encode_utf16() {
            match unit {
                0 => encoded.extend_from_slice(&[0xC0, 0x80]),
                1..=0x7F => encoded.push(unit as u8),
                0x80..=0x7FF => {
                    encoded.push(0xC0 | ((unit >> 6) as u8));
                    encoded.push(0x80 | ((unit & 0x3F) as u8));
                }
                _ => {
                    encoded.push(0xE0 | ((unit >> 12) as u8));
                    encoded.push(0x80 | (((unit >> 6) & 0x3F) as u8));
                    encoded.push(0x80 | ((unit & 0x3F) as u8));
                }
            }
        }
        Some(encoded)
    }

    pub(crate) fn utf8(&mut self, s: &str) -> u16 {
        if let Some(i) = self.utf8.get(s) {
            return *i;
        }
        let Some(encoded_len) = Self::modified_utf8_len(s) else {
            return self.refuse("constant pool UTF-8 entry length overflows");
        };
        let Ok(encoded_len_u16) = u16::try_from(encoded_len) else {
            return self.refuse("constant pool UTF-8 entry exceeds u16 byte length");
        };
        let entry_len: usize = encoded_len.saturating_add(3);
        let Some(idx) = self.reserve_entry(entry_len, 1) else {
            return 0;
        };
        let Some(encoded) = Self::encode_modified_utf8(s, encoded_len) else {
            return self.refuse("constant pool allocation failed");
        };
        let mut entry: Vec<u8> = Vec::new();
        if entry.try_reserve_exact(entry_len).is_err() {
            return self.refuse("constant pool allocation failed");
        }
        entry.push(1);
        entry.extend_from_slice(&encoded_len_u16.to_be_bytes());
        entry.extend_from_slice(&encoded);
        self.commit_entry(idx, entry, 1);
        self.utf8.insert(s.to_string(), idx);
        idx
    }

    fn class(&mut self, internal: &str) -> u16 {
        if let Some(i) = self.class.get(internal) {
            return *i;
        }
        let name_idx: u16 = self.utf8(internal);
        if name_idx == 0 {
            return 0;
        }
        let bytes: [u8; 3] = [7, name_idx.to_be_bytes()[0], name_idx.to_be_bytes()[1]];
        let idx: u16 = self.push_bytes(&bytes, 1);
        if idx != 0 {
            self.class.insert(internal.to_string(), idx);
        }
        idx
    }

    fn name_and_type(&mut self, name: &str, descriptor: &str) -> u16 {
        let n: u16 = self.utf8(name);
        let d: u16 = self.utf8(descriptor);
        if n == 0 || d == 0 {
            return 0;
        }
        if let Some(i) = self.name_and_type.get(&(n, d)) {
            return *i;
        }
        let [n0, n1]: [u8; 2] = n.to_be_bytes();
        let [d0, d1]: [u8; 2] = d.to_be_bytes();
        let idx: u16 = self.push_bytes(&[12, n0, n1, d0, d1], 1);
        if idx != 0 {
            self.name_and_type.insert((n, d), idx);
        }
        idx
    }

    pub(crate) fn methodref(&mut self, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        self.member_ref(10, class_internal, name, descriptor)
    }

    pub(crate) fn interface_methodref(
        &mut self,
        class_internal: &str,
        name: &str,
        descriptor: &str,
    ) -> u16 {
        self.member_ref(11, class_internal, name, descriptor)
    }

    fn member_ref(&mut self, tag: u8, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        let c: u16 = self.class(class_internal);
        let nt: u16 = self.name_and_type(name, descriptor);
        if c == 0 || nt == 0 {
            return 0;
        }
        if let Some(i) = self.methodref.get(&(tag, c, nt)) {
            return *i;
        }
        let [c0, c1]: [u8; 2] = c.to_be_bytes();
        let [n0, n1]: [u8; 2] = nt.to_be_bytes();
        let idx: u16 = self.push_bytes(&[tag, c0, c1, n0, n1], 1);
        if idx != 0 {
            self.methodref.insert((tag, c, nt), idx);
        }
        idx
    }

    pub(crate) fn fieldref(&mut self, class_internal: &str, name: &str, descriptor: &str) -> u16 {
        let c: u16 = self.class(class_internal);
        let nt: u16 = self.name_and_type(name, descriptor);
        if c == 0 || nt == 0 {
            return 0;
        }
        if let Some(i) = self.fieldref.get(&(c, nt)) {
            return *i;
        }
        let [c0, c1]: [u8; 2] = c.to_be_bytes();
        let [n0, n1]: [u8; 2] = nt.to_be_bytes();
        let idx: u16 = self.push_bytes(&[9, c0, c1, n0, n1], 1);
        if idx != 0 {
            self.fieldref.insert((c, nt), idx);
        }
        idx
    }

    pub(crate) fn string(&mut self, s: &str) -> u16 {
        if let Some(i) = self.string.get(s) {
            return *i;
        }
        let utf8_idx: u16 = self.utf8(s);
        if utf8_idx == 0 {
            return 0;
        }
        let [u0, u1]: [u8; 2] = utf8_idx.to_be_bytes();
        let idx: u16 = self.push_bytes(&[8, u0, u1], 1);
        if idx != 0 {
            self.string.insert(s.to_string(), idx);
        }
        idx
    }

    pub(crate) fn class_const(&mut self, internal: &str) -> u16 {
        self.class(internal)
    }

    pub(crate) fn integer(&mut self, value: i32) -> u16 {
        if let Some(i) = self.integer.get(&value) {
            return *i;
        }
        let mut bytes: [u8; 5] = [0; 5];
        bytes[0] = 3;
        bytes[1..].copy_from_slice(&value.to_be_bytes());
        let idx: u16 = self.push_bytes(&bytes, 1);
        if idx != 0 {
            self.integer.insert(value, idx);
        }
        idx
    }

    pub(crate) fn long(&mut self, value: i64) -> u16 {
        if let Some(i) = self.long.get(&value) {
            return *i;
        }
        let mut bytes: [u8; 9] = [0; 9];
        bytes[0] = 5;
        bytes[1..].copy_from_slice(&value.to_be_bytes());
        let idx: u16 = self.push_bytes(&bytes, 2);
        if idx != 0 {
            self.long.insert(value, idx);
        }
        idx
    }

    pub(crate) fn float_bits(&mut self, bits: u32) -> u16 {
        if let Some(i) = self.float.get(&bits) {
            return *i;
        }
        let mut bytes: [u8; 5] = [0; 5];
        bytes[0] = 4;
        bytes[1..].copy_from_slice(&bits.to_be_bytes());
        let idx: u16 = self.push_bytes(&bytes, 1);
        if idx != 0 {
            self.float.insert(bits, idx);
        }
        idx
    }

    pub(crate) fn double_bits(&mut self, bits: u64) -> u16 {
        if let Some(i) = self.double.get(&bits) {
            return *i;
        }
        let mut bytes: [u8; 9] = [0; 9];
        bytes[0] = 6;
        bytes[1..].copy_from_slice(&bits.to_be_bytes());
        let idx: u16 = self.push_bytes(&bytes, 2);
        if idx != 0 {
            self.double.insert(bits, idx);
        }
        idx
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(self.serialized_bytes);
        let count: u16 = u16::try_from(self.entries.len() + 1).unwrap_or(0);
        out.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(entry);
        }
        out
    }
}

fn descriptor_return_is_void(descriptor: &str) -> bool {
    descriptor.rsplit(')').next() == Some("V")
}

fn append_class_bytes(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<()> {
    let actual: usize = out.len().saturating_add(bytes.len());
    if actual > limit {
        return Err(Error::Dex2JarLimit {
            kind: "class bytes",
            actual,
            limit,
        });
    }
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Dex2JarLimit {
            kind: "class bytes",
            actual: usize::MAX,
            limit,
        })?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn stub_code(cp: &mut ConstantPool) -> (Vec<u8>, u16) {
    let uoe_ctor: u16 = cp.methodref("java/lang/UnsupportedOperationException", "<init>", "()V");
    let uoe_class: u16 = cp.class("java/lang/UnsupportedOperationException");
    let mut code: Vec<u8> = Vec::new();
    code.push(0xBB);
    code.extend_from_slice(&uoe_class.to_be_bytes());
    code.push(0x59);
    code.push(0xB7);
    code.extend_from_slice(&uoe_ctor.to_be_bytes());
    code.push(0xBF);
    (code, 2)
}

struct BuiltBody {
    code: Vec<u8>,
    max_stack: u16,
    max_locals: u16,
    sub_attrs: Vec<u8>,
    sub_attr_count: u16,
    exception_table: Vec<u8>,
    exception_count: u16,
    recovered: bool,
    refusal: Option<&'static str>,
}

fn build_real_or_stub_body(
    dex: &DexFile,
    cp: &mut ConstantPool,
    method: &TranslatedMethod,
    code_item: Option<&CodeItem>,
) -> BuiltBody {
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    if let Some(item) = code_item {
        let emitted: Option<EmittedCode> = emit_method_code(dex, cp, item, is_static)
            .or_else(|| emit_branch_method_code(dex, cp, item, is_static));
        if let Some(emitted) = emitted {
            return BuiltBody {
                code: emitted.bytes,
                max_stack: emitted.max_stack,
                max_locals: emitted.max_locals,
                sub_attrs: emitted.attributes,
                sub_attr_count: emitted.attribute_count,
                exception_table: emitted.exception_table,
                exception_count: emitted.exception_count,
                recovered: true,
                refusal: None,
            };
        }
    }
    let (code, max_stack): (Vec<u8>, u16) = stub_code(cp);
    BuiltBody {
        code,
        max_stack,
        max_locals: method_local_slots(method),
        sub_attrs: Vec::new(),
        sub_attr_count: 0,
        exception_table: Vec::new(),
        exception_count: 0,
        recovered: false,
        refusal: Some(if code_item.is_some() {
            "DR-JVM-0093: linear and control-flow JVM emitters refused the decoded body"
        } else {
            "DR-JVM-0093: DEX code parser produced no body for a method requiring code"
        }),
    }
}

fn build_method_attr(
    dex: &DexFile,
    cp: &mut ConstantPool,
    method: &TranslatedMethod,
    is_interface: bool,
    code_item: Option<&CodeItem>,
    max_class_bytes: usize,
) -> Result<(Vec<u8>, bool, Option<&'static str>)> {
    let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
        && !(is_interface && method.access_flags & ACC_STATIC == 0);
    let mut out: Vec<u8> = Vec::new();
    append_class_bytes(
        &mut out,
        &method.access_flags.to_be_bytes(),
        max_class_bytes,
    )?;
    append_class_bytes(
        &mut out,
        &cp.utf8(&method.name).to_be_bytes(),
        max_class_bytes,
    )?;
    append_class_bytes(
        &mut out,
        &cp.utf8(&method.descriptor).to_be_bytes(),
        max_class_bytes,
    )?;
    let mut recovered: bool = false;
    let mut refusal: Option<&'static str> = None;
    if needs_code {
        let body: BuiltBody = build_real_or_stub_body(dex, cp, method, code_item);
        recovered = body.recovered;
        refusal = body.refusal;
        let code_attr_name: u16 = cp.utf8("Code");
        let mut code_attr: Vec<u8> = Vec::new();
        append_class_bytes(
            &mut code_attr,
            &body.max_stack.to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(
            &mut code_attr,
            &body.max_locals.to_be_bytes(),
            max_class_bytes,
        )?;
        let code_len: u32 = u32::try_from(body.code.len())
            .map_err(|_| malformed(&method.name, "method code length exceeds u32"))?;
        append_class_bytes(&mut code_attr, &code_len.to_be_bytes(), max_class_bytes)?;
        append_class_bytes(&mut code_attr, &body.code, max_class_bytes)?;
        append_class_bytes(
            &mut code_attr,
            &body.exception_count.to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(&mut code_attr, &body.exception_table, max_class_bytes)?;
        append_class_bytes(
            &mut code_attr,
            &body.sub_attr_count.to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(&mut code_attr, &body.sub_attrs, max_class_bytes)?;
        append_class_bytes(&mut out, &1u16.to_be_bytes(), max_class_bytes)?;
        append_class_bytes(&mut out, &code_attr_name.to_be_bytes(), max_class_bytes)?;
        let attr_len: u32 = u32::try_from(code_attr.len())
            .map_err(|_| malformed(&method.name, "method attribute length exceeds u32"))?;
        append_class_bytes(&mut out, &attr_len.to_be_bytes(), max_class_bytes)?;
        append_class_bytes(&mut out, &code_attr, max_class_bytes)?;
    } else {
        append_class_bytes(&mut out, &0u16.to_be_bytes(), max_class_bytes)?;
    }
    let _ = descriptor_return_is_void;
    Ok((out, recovered, refusal))
}

fn method_parameter_slots(method: &TranslatedMethod) -> usize {
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let mut slots: usize = usize::from(!is_static);
    let inner: &str = method
        .descriptor
        .split_once('(')
        .and_then(|(_, rest): (&str, &str)| rest.split_once(')'))
        .map(|(p, _): (&str, &str)| p)
        .unwrap_or("");
    let bytes: &[u8] = inner.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' {
                    i += 1;
                }
                i += 1;
                slots = slots.saturating_add(1);
            }
            b'[' => {
                i += 1;
                while i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' {
                        i += 1;
                    }
                }
                i += 1;
                slots = slots.saturating_add(1);
            }
            b'J' | b'D' => {
                i += 1;
                slots = slots.saturating_add(2);
            }
            _ => {
                i += 1;
                slots = slots.saturating_add(1);
            }
        }
    }
    slots
}

fn method_local_slots(method: &TranslatedMethod) -> u16 {
    u16::try_from(method_parameter_slots(method))
        .unwrap_or(u16::MAX)
        .max(1)
}

type MethodKey = (String, String);
type StubbedMethod = (String, &'static str);

fn write_class_file(
    dex: &DexFile,
    class: &TranslatedClass,
    code_items: &BTreeMap<MethodKey, CodeItem>,
    max_class_bytes: usize,
) -> Result<(Vec<u8>, usize, usize, Vec<StubbedMethod>)> {
    if class.fields.len() > usize::from(u16::MAX) {
        return Err(malformed(
            &class.internal_name,
            "field count exceeds classfile limit",
        ));
    }
    if class.methods.len() > usize::from(u16::MAX) {
        return Err(malformed(
            &class.internal_name,
            "method count exceeds classfile limit",
        ));
    }
    if class.interfaces.len() > usize::from(u16::MAX) {
        return Err(malformed(
            &class.internal_name,
            "interface count exceeds classfile limit",
        ));
    }
    if class
        .methods
        .iter()
        .any(|method: &TranslatedMethod| method_parameter_slots(method) > 255)
    {
        return Err(malformed(
            &class.internal_name,
            "method parameter slots exceed JVM limit",
        ));
    }
    let mut cp: ConstantPool = ConstantPool::with_limit(max_class_bytes);
    let this_class: u16 = cp.class(&class.internal_name);
    let super_class: u16 = cp.class(&class.super_name);
    let interface_bytes: usize = class.interfaces.len().saturating_mul(size_of::<u16>());
    if interface_bytes > max_class_bytes {
        return Err(Error::Dex2JarLimit {
            kind: "class bytes",
            actual: interface_bytes,
            limit: max_class_bytes,
        });
    }
    let mut interface_indices: Vec<u16> = Vec::new();
    interface_indices
        .try_reserve_exact(class.interfaces.len())
        .map_err(|_| Error::Dex2JarLimit {
            kind: "class bytes",
            actual: usize::MAX,
            limit: max_class_bytes,
        })?;
    for interface in &class.interfaces {
        interface_indices.push(cp.class(interface));
    }
    let is_interface: bool = class.is_interface();
    let mut field_section: Vec<u8> = Vec::new();
    append_class_bytes(
        &mut field_section,
        &u16::try_from(class.fields.len())
            .map_err(|_| malformed(&class.internal_name, "field count exceeds classfile limit"))?
            .to_be_bytes(),
        max_class_bytes,
    )?;
    for field in &class.fields {
        append_class_bytes(
            &mut field_section,
            &field.access_flags.to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(
            &mut field_section,
            &cp.utf8(&field.name).to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(
            &mut field_section,
            &cp.utf8(&field.descriptor).to_be_bytes(),
            max_class_bytes,
        )?;
        append_class_bytes(&mut field_section, &0u16.to_be_bytes(), max_class_bytes)?;
    }
    let mut method_section: Vec<u8> = Vec::new();
    append_class_bytes(
        &mut method_section,
        &u16::try_from(class.methods.len())
            .map_err(|_| malformed(&class.internal_name, "method count exceeds classfile limit"))?
            .to_be_bytes(),
        max_class_bytes,
    )?;
    let mut recovered: usize = 0;
    let mut stubbed: usize = 0;
    let mut stubbed_methods: Vec<StubbedMethod> = Vec::new();
    for method in &class.methods {
        let key: MethodKey = (method.name.clone(), method.descriptor.clone());
        let code_item: Option<&CodeItem> = code_items.get(&key);
        let (attr, real, refusal): (Vec<u8>, bool, Option<&'static str>) = build_method_attr(
            dex,
            &mut cp,
            method,
            is_interface,
            code_item,
            max_class_bytes,
        )?;
        if real {
            recovered += 1;
        }
        if let Some(reason) = refusal {
            stubbed += 1;
            stubbed_methods.push((format!("{}{}", method.name, method.descriptor), reason));
        }
        append_class_bytes(&mut method_section, &attr, max_class_bytes)?;
    }

    let mut access: u16 = class.access_flags;
    if !is_interface {
        access |= ACC_SUPER;
    }

    cp.check(&class.internal_name)?;
    let constant_pool: Vec<u8> = cp.serialize();
    let mut out: Vec<u8> = Vec::new();
    append_class_bytes(&mut out, &0xCAFE_BABEu32.to_be_bytes(), max_class_bytes)?;
    append_class_bytes(
        &mut out,
        &CLASS_VERSION_MINOR.to_be_bytes(),
        max_class_bytes,
    )?;
    append_class_bytes(
        &mut out,
        &CLASS_VERSION_MAJOR.to_be_bytes(),
        max_class_bytes,
    )?;
    append_class_bytes(&mut out, &constant_pool, max_class_bytes)?;
    append_class_bytes(&mut out, &access.to_be_bytes(), max_class_bytes)?;
    append_class_bytes(&mut out, &this_class.to_be_bytes(), max_class_bytes)?;
    append_class_bytes(&mut out, &super_class.to_be_bytes(), max_class_bytes)?;
    append_class_bytes(
        &mut out,
        &u16::try_from(interface_indices.len())
            .map_err(|_| {
                malformed(
                    &class.internal_name,
                    "interface count exceeds classfile limit",
                )
            })?
            .to_be_bytes(),
        max_class_bytes,
    )?;
    for i in &interface_indices {
        append_class_bytes(&mut out, &i.to_be_bytes(), max_class_bytes)?;
    }
    append_class_bytes(&mut out, &field_section, max_class_bytes)?;
    append_class_bytes(&mut out, &method_section, max_class_bytes)?;
    append_class_bytes(&mut out, &0u16.to_be_bytes(), max_class_bytes)?;
    Ok((out, recovered, stubbed, stubbed_methods))
}

fn code_items_by_class(items: Vec<CodeItem>) -> BTreeMap<String, BTreeMap<MethodKey, CodeItem>> {
    let mut out: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = BTreeMap::new();
    for item in items {
        let class_internal: String = dex_type_to_internal(&item.class);
        let key: MethodKey = (item.method_name.clone(), item.method_descriptor.clone());
        out.entry(class_internal).or_default().insert(key, item);
    }
    out
}

pub fn translate(dex: &DexFile, dex_bytes: &[u8]) -> Result<Dex2JarResult> {
    translate_with_limits(dex, dex_bytes, Dex2JarLimits::default())
}

pub fn translate_with_limits(
    dex: &DexFile,
    dex_bytes: &[u8],
    limits: Dex2JarLimits,
) -> Result<Dex2JarResult> {
    validate_preparse_limits(&dex.header, dex_bytes, limits)?;
    validate_parsed_tables(dex)?;
    let mut allocation_budget: AllocationBudget =
        parsed_allocation_budget(dex, translation_allocation_limit(limits))?;
    let classes: Vec<TranslatedClass> =
        build_class_model_with_budget(dex, dex_bytes, &mut allocation_budget)?;
    let code_report: crate::dex::CodeItemsReport = parse_code_items(dex, dex_bytes);
    let code_scan_complete: bool = code_report.is_fully_decoded();
    let decode_error_count: usize = code_report.error_count();
    let mut diagnostics: BTreeMap<(String, Option<String>), String> = BTreeMap::new();
    for method in code_report.methods() {
        if let crate::dex::DexCodeState::Refused(error) = &method.state {
            diagnostics.insert(
                (
                    dex_type_to_internal(&method.class),
                    Some(format!(
                        "{}{}",
                        method.method_name, method.method_descriptor
                    )),
                ),
                error.to_string(),
            );
        }
    }
    if let Some(tail) = code_report.unrecovered_tail() {
        diagnostics.insert(
            (dex_type_to_internal(&tail.class), None),
            tail.error.to_string(),
        );
    }
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> =
        code_items_by_class(code_report.into_partial_decoded());
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut jar_entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut method_total: usize = 0;
    let mut bodies_recovered: usize = 0;
    let mut stubbed_body_count: usize = 0;
    let mut class_bytes_total: usize = 0;
    for class in &classes {
        if jar_entries.len() >= limits.classes {
            return Err(Error::Dex2JarLimit {
                kind: "class count",
                actual: jar_entries.len().saturating_add(1),
                limit: limits.classes,
            });
        }
        method_total += class.methods.len();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        let remaining: usize = limits.class_bytes.saturating_sub(class_bytes_total);
        let (class_bytes, recovered, stubbed, stubbed_methods): (
            Vec<u8>,
            usize,
            usize,
            Vec<StubbedMethod>,
        ) = write_class_file(dex, class, code_items, remaining)?;
        bodies_recovered += recovered;
        stubbed_body_count += stubbed;
        if !stubbed_methods.is_empty() {
            for (method, reason) in stubbed_methods {
                diagnostics
                    .entry((class.internal_name.clone(), Some(method)))
                    .or_insert_with(|| reason.to_owned());
            }
        }
        let path: String = format!("{}.class", class.internal_name);
        if jar_entries.contains_key(&path) {
            return Err(Error::DuplicateDex2JarPath(path));
        }
        let next: usize =
            class_bytes_total
                .checked_add(class_bytes.len())
                .ok_or(Error::Dex2JarLimit {
                    kind: "class bytes",
                    actual: usize::MAX,
                    limit: limits.class_bytes,
                })?;
        if next > limits.class_bytes {
            return Err(Error::Dex2JarLimit {
                kind: "class bytes",
                actual: next,
                limit: limits.class_bytes,
            });
        }
        class_bytes_total = next;
        jar_entries.insert(path, class_bytes);
    }
    let diagnostics: Vec<Dex2JarDiagnostic> = diagnostics
        .into_iter()
        .map(
            |((class, method), reason): ((String, Option<String>), String)| Dex2JarDiagnostic {
                class,
                method,
                reason,
            },
        )
        .collect();
    Ok(Dex2JarResult {
        classes,
        jar_entries,
        method_total,
        bodies_recovered,
        stubbed_body_count,
        code_scan_complete,
        decode_error_count,
        diagnostics,
    })
}

pub fn assemble_jar(result: &Dex2JarResult) -> Result<Vec<u8>> {
    assemble_jar_with_limit(result, Dex2JarLimits::default().jar_bytes)
}

pub fn assemble_jar_with_limit(result: &Dex2JarResult, max_jar_bytes: usize) -> Result<Vec<u8>> {
    use zip::write::SimpleFileOptions;
    validate_dex2jar_entries(&result.jar_entries)?;
    let writer = LimitedWriter {
        bytes: Vec::new(),
        limit: max_jar_bytes,
        position: 0,
        logical_len: 0,
        overflowed: false,
    };
    let mut zip: zip::ZipWriter<LimitedWriter> = zip::ZipWriter::new(writer);
    let opts: SimpleFileOptions =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("META-INF/MANIFEST.MF", opts)
        .map_err(|error| Error::Zip(error.to_string()))?;
    zip.write_all(b"Manifest-Version: 1.0\r\nCreated-By: disrobe dex2jar\r\n\r\n")?;
    for (name, data) in &result.jar_entries {
        zip.start_file(name.as_str(), opts)
            .map_err(|error| Error::Zip(error.to_string()))?;
        zip.write_all(data)?;
    }
    let writer: LimitedWriter = zip
        .finish()
        .map_err(|error| Error::Zip(error.to_string()))?;
    if writer.overflowed {
        return Err(Error::Dex2JarLimit {
            kind: "JAR bytes",
            actual: usize::try_from(writer.logical_len).unwrap_or(usize::MAX),
            limit: max_jar_bytes,
        });
    }
    Ok(writer.bytes)
}

pub fn translate_dex_bytes(dex_bytes: &[u8]) -> Result<Dex2JarResult> {
    translate_dex_bytes_with_limits(dex_bytes, Dex2JarLimits::default())
}

pub fn translate_dex_bytes_with_limits(
    dex_bytes: &[u8],
    limits: Dex2JarLimits,
) -> Result<Dex2JarResult> {
    if dex_bytes.len() > limits.input_bytes {
        return Err(Error::Dex2JarLimit {
            kind: "input bytes",
            actual: dex_bytes.len(),
            limit: limits.input_bytes,
        });
    }
    let header: crate::dex::DexHeader = crate::dex::parse_header(dex_bytes)?;
    validate_preparse_limits(&header, dex_bytes, limits)?;
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    translate_with_limits(&dex, dex_bytes, limits)
}

pub fn validate_dex2jar_entries(entries: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let mut portable: BTreeMap<String, &str> = BTreeMap::new();
    for raw in entries.keys() {
        let mut parts: std::str::Split<'_, char> = raw.split('/');
        let mut seen_part: bool = false;
        for part in &mut parts {
            seen_part = true;
            if !portable_component(part) {
                return Err(Error::UnsafeDex2JarPath(raw.clone()));
            }
        }
        if !seen_part || !raw.ends_with(".class") {
            return Err(Error::UnsafeDex2JarPath(raw.clone()));
        }
        let key: String = raw.to_ascii_lowercase();
        if portable.insert(key, raw).is_some() {
            return Err(Error::UnsafeDex2JarPath(raw.clone()));
        }
    }
    Ok(())
}

fn portable_component(part: &str) -> bool {
    if part.is_empty()
        || part == "."
        || part == ".."
        || part.contains("..")
        || part.ends_with(['.', ' '])
    {
        return false;
    }
    if !part
        .bytes()
        .all(|byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'-' | b'.'))
    {
        return false;
    }
    let base_part: &str = part.split_once('.').map_or(part, |(before, _)| before);
    if base_part.ends_with(['.', ' ']) {
        return false;
    }
    let base: String = base_part.to_ascii_uppercase();
    !matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
        && !(base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(any(test, feature = "lifter-diag"))]
pub fn diagnose_dex_bytes(dex_bytes: &[u8]) -> Result<BTreeMap<String, usize>> {
    use crate::dalvik::decode_method;
    use crate::dalvik_to_jvm::{
        emit_branch_method_code, emit_method_code, reset_bail_op, take_bail_kind, take_bail_op,
    };
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    let classes: Vec<TranslatedClass> = build_class_model(&dex, dex_bytes)?;
    let items: Vec<CodeItem> = parse_code_items(&dex, dex_bytes).into_complete()?;
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = code_items_by_class(items);
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
    for class in &classes {
        let is_interface: bool = class.is_interface();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        for method in &class.methods {
            let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
                && !(is_interface && method.access_flags & ACC_STATIC == 0);
            if !needs_code {
                continue;
            }
            let key: MethodKey = (method.name.clone(), method.descriptor.clone());
            let Some(item): Option<&CodeItem> = code_items.get(&key) else {
                *buckets.entry("no-code-item".to_string()).or_default() += 1;
                continue;
            };
            let is_static: bool = method.access_flags & ACC_STATIC != 0;
            let mut cp: ConstantPool = ConstantPool::default();
            reset_bail_op();
            let linear: Option<EmittedCode> = emit_method_code(&dex, &mut cp, item, is_static);
            if linear.is_some() {
                continue;
            }
            reset_bail_op();
            let branch: Option<EmittedCode> =
                emit_branch_method_code(&dex, &mut cp, item, is_static);
            if branch.is_some() {
                continue;
            }
            let width_conflict: bool =
                crate::dalvik_to_jvm::diag_has_width_conflict(&dex, item, is_static);
            let label: String = classify_stub(
                &dex,
                item,
                take_bail_op(),
                take_bail_kind(),
                width_conflict,
                &decode_method,
            );
            *buckets.entry(label).or_default() += 1;
        }
    }
    Ok(buckets)
}

#[cfg(any(test, feature = "lifter-diag"))]
pub fn diagnose_dex_methods(dex_bytes: &[u8]) -> Result<Vec<(String, String, String, String)>> {
    use crate::dalvik::decode_method;
    use crate::dalvik_to_jvm::{
        emit_branch_method_code, emit_method_code, reset_bail_op, take_bail_kind, take_bail_op,
    };
    let dex: DexFile = crate::dex::parse(dex_bytes)?;
    let classes: Vec<TranslatedClass> = build_class_model(&dex, dex_bytes)?;
    let items: Vec<CodeItem> = parse_code_items(&dex, dex_bytes).into_complete()?;
    let code_by_class: BTreeMap<String, BTreeMap<MethodKey, CodeItem>> = code_items_by_class(items);
    let empty: BTreeMap<MethodKey, CodeItem> = BTreeMap::new();
    let mut out: Vec<(String, String, String, String)> = Vec::new();
    for class in &classes {
        let is_interface: bool = class.is_interface();
        let code_items: &BTreeMap<MethodKey, CodeItem> =
            code_by_class.get(&class.internal_name).unwrap_or(&empty);
        for method in &class.methods {
            let needs_code: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) == 0
                && !(is_interface && method.access_flags & ACC_STATIC == 0);
            if !needs_code {
                continue;
            }
            let key: MethodKey = (method.name.clone(), method.descriptor.clone());
            let Some(item): Option<&CodeItem> = code_items.get(&key) else {
                continue;
            };
            let is_static: bool = method.access_flags & ACC_STATIC != 0;
            let mut cp: ConstantPool = ConstantPool::default();
            reset_bail_op();
            if emit_method_code(&dex, &mut cp, item, is_static).is_some() {
                continue;
            }
            reset_bail_op();
            if emit_branch_method_code(&dex, &mut cp, item, is_static).is_some() {
                continue;
            }
            let branch_bail_op: i32 = take_bail_op();
            let branch_bail_kind: &str = take_bail_kind();
            let width_conflict: bool =
                crate::dalvik_to_jvm::diag_has_width_conflict(&dex, item, is_static);
            let label: String = classify_stub(
                &dex,
                item,
                branch_bail_op,
                branch_bail_kind,
                width_conflict,
                &decode_method,
            );
            let mnemonics: String = decode_method(&item.insns)
                .iter()
                .map(|i: &crate::dalvik::DalvikInsn| i.mnemonic)
                .collect::<Vec<&str>>()
                .join(" ");
            out.push((
                class.internal_name.clone(),
                method.name.clone(),
                format!("{label} | {mnemonics}"),
                method.descriptor.clone(),
            ));
        }
    }
    Ok(out)
}

#[cfg(any(test, feature = "lifter-diag"))]
fn classify_stub(
    dex: &DexFile,
    item: &CodeItem,
    bail_op: i32,
    bail_kind: &str,
    width_conflict: bool,
    decode: &dyn Fn(&[u16]) -> Vec<crate::dalvik::DalvikInsn>,
) -> String {
    use crate::dalvik::DalvikInsn;
    let insns: Vec<DalvikInsn> = decode(&item.insns);
    if insns.is_empty() {
        return "empty-or-undecodable".to_string();
    }
    if bail_op >= 0 {
        if !bail_kind.is_empty() {
            return format!("emit-bail-{bail_kind}");
        }
        return format!("emit-bail-op-{:#04x}", bail_op as u8);
    }
    if width_conflict {
        return "width-conflict".to_string();
    }
    if crate::dalvik_to_jvm::diag_is_synthetic_class(&item.class) {
        return "synthetic-class-rejected".to_string();
    }
    let has_branch: bool = insns.iter().any(|i: &DalvikInsn| {
        i.is_conditional_branch() || i.is_unconditional_goto() || i.is_switch()
    });
    let has_try: bool = !item.tries.is_empty();
    let is_init: bool = item.method_name == "<init>";
    if (has_branch || has_try) && is_init {
        return "init-ctor-gate".to_string();
    }
    if has_branch || has_try {
        if insns.iter().any(|i: &DalvikInsn| i.op == 0x26) {
            return "branch-gate-fill-array-data".to_string();
        }
        if has_try {
            return "branch-gate-try".to_string();
        }
        if insns.iter().any(|i: &DalvikInsn| i.op == 0x22) {
            return "branch-gate-new-instance".to_string();
        }
        if insns.iter().any(|i: &DalvikInsn| i.is_switch()) {
            return "branch-gate-switch".to_string();
        }
        return "branch-gate-typestate-or-stackmap".to_string();
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x22) {
        return "linear-new-instance".to_string();
    }
    if insns.iter().any(|i: &DalvikInsn| i.op == 0x0D) {
        return "linear-move-exception".to_string();
    }
    let last: usize = insns.len() - 1;
    if insns
        .iter()
        .take(last)
        .any(|i: &DalvikInsn| matches!(i.op, 0x0E..=0x11 | 0x27))
    {
        return "linear-early-return-or-throw".to_string();
    }
    let _ = dex;
    let dominant: u8 = insns.iter().map(|i: &DalvikInsn| i.op).max().unwrap_or(0);
    format!("linear-struct-max-op-{dominant:#04x}")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex_builder::{
        ClassDef, DexBuilder, EncodedField, EncodedMethod, FieldRef, MethodRef, ProtoRef,
    };

    #[test]
    fn dex_type_to_internal_strips_l_and_semicolon() {
        assert_eq!(dex_type_to_internal("LFoo/Bar;"), "Foo/Bar");
        assert_eq!(dex_type_to_internal("I"), "I");
    }

    #[test]
    fn local_slots_counts_long_double_as_two() {
        let m: TranslatedMethod = TranslatedMethod {
            name: "x".to_string(),
            descriptor: "(JD)V".to_string(),
            access_flags: ACC_STATIC,
            has_code: true,
        };
        assert_eq!(method_local_slots(&m), 4);
    }

    #[test]
    fn class_data_uleb128_rejects_values_wider_than_u32() {
        let overflow: [u8; 5] = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
        assert!(crate::dex::read_uleb128(&overflow, 0).is_err());
        assert!(crate::dex::read_uleb128(&[0x80], 0).is_err());
    }

    #[test]
    fn translation_reports_incomplete_code_scan() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Invalid;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Invalid;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "body".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x0014],
                relocations: Vec::new(),
            }],
        });
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let result: Dex2JarResult = translate(&dex, &bytes).expect("translate");

        assert!(!result.code_scan_complete);
        assert_eq!(result.decode_error_count, 1);
        assert_eq!(result.bodies_recovered, 0);
        assert_eq!(result.stubbed_body_count, 1);
        let diagnostics: Vec<&Dex2JarDiagnostic> = result
            .diagnostics
            .iter()
            .filter(|diagnostic: &&Dex2JarDiagnostic| {
                diagnostic.class == "com/disrobe/Invalid"
                    && diagnostic.method.as_deref() == Some("body()V")
            })
            .collect();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].reason,
            "DR-JVM-0025: malformed bytecode at offset 260: truncated DEX instruction"
        );
    }

    #[test]
    fn translation_limits_fail_with_typed_errors_before_output_is_materialized() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Limited;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let count = translate_with_limits(
            &dex,
            &bytes,
            Dex2JarLimits {
                input_bytes: usize::MAX,
                classes: 0,
                class_bytes: 1,
                jar_bytes: 1,
            },
        )
        .expect_err("class count limit");
        assert!(matches!(
            count,
            Error::Dex2JarLimit {
                kind: "class count",
                ..
            }
        ));
        let bytes_limit = translate_with_limits(
            &dex,
            &bytes,
            Dex2JarLimits {
                input_bytes: usize::MAX,
                classes: 1,
                class_bytes: 1,
                jar_bytes: 1,
            },
        )
        .expect_err("class byte limit");
        assert!(matches!(
            bytes_limit,
            Error::Dex2JarLimit {
                kind: "class bytes",
                ..
            }
        ));
    }

    #[test]
    fn malformed_class_references_and_members_are_not_silently_dropped() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Malformed;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
        let original: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&original).expect("built dex");
        let class_def: usize = dex.header.class_defs_off as usize;

        let mut super_index: Vec<u8> = original.clone();
        super_index[class_def + 8..class_def + 12].copy_from_slice(&1_000_000_u32.to_le_bytes());
        let error: Error = translate(&dex, &super_index).expect_err("bad superclass index");
        assert!(matches!(
            error,
            Error::MalformedDex2JarClass {
                reason: "superclass type index is out of range",
                ..
            }
        ));

        let mut interface_list: Vec<u8> = original.clone();
        let interface_offset: u32 = interface_list.len() as u32 - 4;
        interface_list[interface_offset as usize..].copy_from_slice(&1_u32.to_le_bytes());
        interface_list[class_def + 12..class_def + 16]
            .copy_from_slice(&interface_offset.to_le_bytes());
        let error: Error = translate(&dex, &interface_list).expect_err("truncated interface list");
        assert!(matches!(
            error,
            Error::MalformedDex2JarClass {
                reason: "interface list is truncated",
                ..
            }
        ));

        let class_data: usize = u32::from_le_bytes(
            original[class_def + 24..class_def + 28]
                .try_into()
                .expect("class data offset"),
        ) as usize;
        let mut member: Vec<u8> = original;
        member[class_data] = 1;
        let error: Error = translate(&dex, &member).expect_err("truncated encoded field");
        assert!(
            matches!(
                error,
                Error::MalformedDex2JarClass {
                    reason: "encoded field index is out of range" | "encoded field is truncated",
                    ..
                }
            ),
            "got {error:?}"
        );
    }

    #[test]
    fn duplicate_internal_class_paths_fail_before_map_insertion() {
        let mut builder: DexBuilder = DexBuilder::new();
        for _ in 0..2 {
            builder.add_class(ClassDef {
                class: "Lcom/disrobe/Duplicate;".to_owned(),
                super_class: "Ljava/lang/Object;".to_owned(),
                access_flags: 0x0001,
                static_fields: Vec::new(),
                static_values: Vec::new(),
                direct_methods: Vec::new(),
                virtual_methods: Vec::new(),
            });
        }
        let bytes: Vec<u8> = builder.build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let error: Error = translate(&dex, &bytes).expect_err("duplicate class path");
        assert!(matches!(
            error,
            Error::DuplicateDex2JarPath(path) if path == "com/disrobe/Duplicate.class"
        ));
    }

    #[test]
    fn bounded_jar_assembly_refuses_a_tiny_limit() {
        let result = Dex2JarResult {
            classes: Vec::new(),
            jar_entries: BTreeMap::new(),
            method_total: 0,
            bodies_recovered: 0,
            stubbed_body_count: 0,
            code_scan_complete: true,
            decode_error_count: 0,
            diagnostics: Vec::new(),
        };
        let error = assemble_jar_with_limit(&result, 1).expect_err("JAR limit");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "JAR bytes",
                ..
            }
        ));
    }

    #[test]
    fn jar_assembly_rejects_an_unportable_entry_before_writing() {
        let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        entries.insert("classes/COM\u{00B9}.class".to_owned(), vec![0xCA, 0xFE]);
        let result = Dex2JarResult {
            classes: Vec::new(),
            jar_entries: entries,
            method_total: 0,
            bodies_recovered: 0,
            stubbed_body_count: 0,
            code_scan_complete: true,
            decode_error_count: 0,
            diagnostics: Vec::new(),
        };
        assert!(matches!(
            assemble_jar_with_limit(&result, 1024),
            Err(Error::UnsafeDex2JarPath(path)) if path == "classes/COM\u{00B9}.class"
        ));
    }

    #[test]
    fn byte_entrypoint_enforces_input_limit_before_parsing() {
        let error: Error = translate_dex_bytes_with_limits(
            b"not a dex",
            Dex2JarLimits {
                input_bytes: 1,
                classes: 1,
                class_bytes: 1,
                jar_bytes: 1,
            },
        )
        .expect_err("the byte limit must win before DEX parsing");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "input bytes",
                actual: 9,
                limit: 1,
            }
        ));
    }

    #[test]
    fn byte_entrypoint_rejects_declared_table_work_before_general_parsing() {
        let mut bytes: Vec<u8> = DexBuilder::new().build();
        bytes[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
        let error: Error = translate_dex_bytes_with_limits(
            &bytes,
            Dex2JarLimits {
                input_bytes: 1024,
                classes: usize::MAX,
                class_bytes: 1024,
                jar_bytes: usize::MAX,
            },
        )
        .expect_err("declared method table budget");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "DEX table bytes",
                ..
            }
        ));
    }

    #[test]
    fn byte_entrypoint_rejects_per_method_prototype_amplification_before_parsing() {
        let prototype: ProtoRef = ProtoRef {
            return_type: "V".to_owned(),
            params: vec!["I".to_owned(); 256],
        };
        let methods: Vec<EncodedMethod> = (0..128)
            .map(|index: usize| EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Amplified;".to_owned(),
                    proto: prototype.clone(),
                    name: format!("body{index}"),
                },
                access_flags: 0x0401,
                is_direct: false,
                registers_size: 0,
                ins_size: 0,
                outs_size: 0,
                insns: Vec::new(),
                relocations: Vec::new(),
            })
            .collect();
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Amplified;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: methods,
        });
        let bytes: Vec<u8> = builder.build();
        let error: Error = translate_dex_bytes_with_limits(
            &bytes,
            Dex2JarLimits {
                input_bytes: bytes.len(),
                classes: 1,
                class_bytes: usize::MAX,
                jar_bytes: usize::MAX,
            },
        )
        .expect_err("per-method prototype allocation");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "DEX parse allocation",
                ..
            }
        ));
    }

    #[test]
    fn parsed_entrypoint_rejects_table_vectors_that_disagree_with_the_header() {
        let bytes: Vec<u8> = DexBuilder::new().build();
        let mut dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        dex.strings.push("unreported".to_owned());
        let error: Error = translate_with_limits(&dex, &bytes, Dex2JarLimits::default())
            .expect_err("parsed table mismatch");
        assert!(matches!(
            error,
            Error::MalformedDex2JarClass {
                reason: "parsed string table does not match the DEX header",
                ..
            }
        ));
    }

    #[test]
    fn parsed_entrypoint_rejects_per_method_prototype_amplification() {
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: "Lcom/disrobe/Amplified;".to_owned(),
            super_class: "Ljava/lang/Object;".to_owned(),
            access_flags: 0x0001,
            static_fields: Vec::new(),
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: vec![EncodedMethod {
                tries: Vec::new(),
                method: MethodRef {
                    class: "Lcom/disrobe/Amplified;".to_owned(),
                    proto: ProtoRef {
                        return_type: "V".to_owned(),
                        params: Vec::new(),
                    },
                    name: "body".to_owned(),
                },
                access_flags: 0x0001,
                is_direct: false,
                registers_size: 1,
                ins_size: 0,
                outs_size: 0,
                insns: vec![0x000E],
                relocations: Vec::new(),
            }],
        });
        let bytes: Vec<u8> = builder.build();
        let mut dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        dex.method_ids[0].proto.parameters = vec!["I".to_owned(); 4_096];
        let error: Error = translate_with_limits(
            &dex,
            &bytes,
            Dex2JarLimits {
                input_bytes: bytes.len(),
                classes: 1,
                class_bytes: usize::MAX,
                jar_bytes: usize::MAX,
            },
        )
        .expect_err("per-method prototype allocation");
        assert!(matches!(
            error,
            Error::Dex2JarLimit {
                kind: "DEX translation allocation",
                ..
            }
        ));
    }

    #[test]
    fn preparse_accounts_for_field_class_and_superclass_string_clones() {
        let class_name: String = format!("L{};", "c".repeat(512));
        let super_name: String = format!("L{};", "s".repeat(512));
        let field_name: String = "f".repeat(512);
        let mut builder: DexBuilder = DexBuilder::new();
        builder.add_class(ClassDef {
            class: class_name.clone(),
            super_class: super_name.clone(),
            access_flags: 0x0001,
            static_fields: vec![EncodedField {
                field: FieldRef {
                    class: class_name.clone(),
                    type_desc: "I".to_owned(),
                    name: field_name.clone(),
                },
                access_flags: 0x0001,
            }],
            static_values: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        });
        let bytes: Vec<u8> = builder.build();
        let header: crate::dex::DexHeader = crate::dex::parse_header(&bytes).expect("header");
        let allocation: usize = preparse_amplified_allocation(&header, &bytes).expect("estimate");
        let dex: DexFile = crate::dex::parse(&bytes).expect("parsed fixture");
        let base_strings: usize = dex.strings.iter().map(String::len).sum::<usize>()
            + dex.type_names.iter().map(String::len).sum::<usize>();
        let required_clones: usize = class_name.len()
            + class_name.len()
            + super_name.len()
            + class_name.len()
            + "I".len()
            + field_name.len();
        assert!(allocation >= base_strings + required_clones);
    }

    #[test]
    fn class_emission_rejects_parameter_slots_above_255_before_stub_emission() {
        let bytes: Vec<u8> = DexBuilder::new().build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        for descriptor in [
            format!("({})V", "I".repeat(255)),
            format!("({})V", "J".repeat(128)),
        ] {
            let class: TranslatedClass = TranslatedClass {
                internal_name: "TooManyParameters".to_owned(),
                super_name: "java/lang/Object".to_owned(),
                interfaces: Vec::new(),
                access_flags: 0x0001,
                fields: Vec::new(),
                methods: vec![TranslatedMethod {
                    name: "body".to_owned(),
                    descriptor,
                    access_flags: 0x0001,
                    has_code: false,
                }],
            };
            let error: Error = write_class_file(&dex, &class, &BTreeMap::new(), usize::MAX)
                .expect_err("JVM parameter-slot limit");
            assert!(matches!(
                error,
                Error::MalformedDex2JarClass {
                    reason: "method parameter slots exceed JVM limit",
                    ..
                }
            ));
        }
    }

    #[test]
    fn constant_pool_utf8_uses_jvm_modified_utf8() {
        let mut pool: ConstantPool = ConstantPool::default();
        assert_eq!(pool.utf8("\0\u{1F600}"), 1);
        assert_eq!(
            pool.serialize(),
            vec![
                0x00, 0x02, 0x01, 0x00, 0x08, 0xC0, 0x80, 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80,
            ]
        );
    }

    #[test]
    fn class_emission_rejects_modified_utf8_lengths_above_u16() {
        let bytes: Vec<u8> = DexBuilder::new().build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let class: TranslatedClass = TranslatedClass {
            internal_name: "TooLong".to_owned(),
            super_name: "java/lang/Object".to_owned(),
            interfaces: Vec::new(),
            access_flags: 0x0001,
            fields: vec![TranslatedField {
                name: "x".repeat(usize::from(u16::MAX) + 1),
                descriptor: "I".to_owned(),
                access_flags: 0x0001,
            }],
            methods: Vec::new(),
        };
        let error: Error = write_class_file(&dex, &class, &BTreeMap::new(), usize::MAX)
            .expect_err("constant-pool UTF-8 length");
        assert!(matches!(
            error,
            Error::MalformedDex2JarClass {
                reason: "constant pool UTF-8 entry exceeds u16 byte length",
                ..
            }
        ));
    }

    #[test]
    fn class_emission_rejects_constant_pool_index_overflow() {
        let bytes: Vec<u8> = DexBuilder::new().build();
        let dex: DexFile = crate::dex::parse(&bytes).expect("built dex");
        let fields: Vec<TranslatedField> = (0..32_768_u32)
            .map(|index: u32| TranslatedField {
                name: format!("f{index}"),
                descriptor: format!("Lx/T{index};"),
                access_flags: 0x0001,
            })
            .collect();
        let class: TranslatedClass = TranslatedClass {
            internal_name: "PoolOverflow".to_owned(),
            super_name: "java/lang/Object".to_owned(),
            interfaces: Vec::new(),
            access_flags: 0x0001,
            fields,
            methods: Vec::new(),
        };
        let error: Error = write_class_file(&dex, &class, &BTreeMap::new(), usize::MAX)
            .expect_err("constant-pool index overflow");
        assert!(matches!(
            error,
            Error::MalformedDex2JarClass {
                reason: "constant pool index exceeds u16",
                ..
            }
        ));
    }

    #[test]
    fn portable_entry_validation_rejects_windows_names_and_case_collisions() {
        for path in [
            "a\\b.class",
            "a/nu\0l.class",
            "a/COM\u{00B9}.class",
            "a/name?.class",
            "a/tail .class",
            "a/tail..class",
            "a/\u{03A3}.class",
            "a/\u{212A}.class",
        ] {
            let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            entries.insert(path.to_owned(), vec![0]);
            assert!(validate_dex2jar_entries(&entries).is_err(), "{path:?}");
        }
        let mut collisions: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        collisions.insert("a/K.class".to_owned(), vec![0]);
        collisions.insert("a/k.class".to_owned(), vec![0]);
        assert!(validate_dex2jar_entries(&collisions).is_err());
    }
}
