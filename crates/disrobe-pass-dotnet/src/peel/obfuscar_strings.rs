use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cil::{
    Instruction, MethodBody, MethodBodyExtent, OperandValue, method_body_code_size,
    method_body_extent, parse_method_body,
};
use crate::metadata::{
    MetadataRoot, StreamHeader, TableStream, parse_metadata_root, parse_table_stream,
};
use crate::model::{AssemblyModel, FieldModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, DataDirectory, PeImage, SectionHeader, parse, parse_clr_header};
use crate::peel::cctor_constants::int_immediate;
use crate::peel::deflatten::decrypt::{init_array_tokens, is_corelib_type_ref};
use crate::peel::string_emu::RecoveredString;
use crate::signature::{SIG_DEFAULT, SIG_HASTHIS, TypeSig, TypeSigOrVoid};
use crate::structurize::TargetLang;
use crate::tables::{RowRef, TableId};

pub(crate) const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_BLOB_BYTES: usize = 64 * 1024 * 1024;
const MAX_MODEL_SIGNATURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_MODEL_NAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_TABLE_ROWS: u64 = 1_000_000;
const MAX_TYPE_ROWS: u32 = 65_536;
const MAX_METHOD_ROWS: u32 = 131_072;
const MAX_FIELD_ROWS: u32 = 131_072;
const MAX_MEMBER_REF_ROWS: u32 = 131_072;
const MAX_TOTAL_METHOD_CODE: usize = 64 * 1024 * 1024;
const MAX_TOTAL_PARSE_BYTES: usize = 72 * 1024 * 1024;
const MAX_TOTAL_INSTRUCTIONS: usize = 1_000_000;
const MAX_TOTAL_EXCEPTION_CLAUSES: usize = 65_536;
const MAX_METHOD_CODE: u32 = 1024 * 1024;
const MAX_METHOD_PARSE_BYTES: usize = 1024 * 1024 + 64 * 1024 + 64;
const MAX_CONSTRUCTOR_CODE: u32 = 16 * 1024;
const MAX_CONSTRUCTOR_INSTRUCTIONS: usize = 2_048;
const MAX_GETTER_CODE: u32 = 4 * 1024;
const MAX_GETTER_INSTRUCTIONS: usize = 256;
const MAX_ACCESSOR_CODE: u32 = 256;
const MAX_ACCESSOR_INSTRUCTIONS: usize = 32;
const MAX_STACK: u16 = 64;
const MAX_FIELD_DATA: usize = 64 * 1024 * 1024;
const MAX_ACCESSORS: usize = 65_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_RECOVERED_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECOVERED_NAME_BYTES: usize = 4 * 1024 * 1024;
const FIELD_STATIC: u16 = 0x0010;
const FIELD_HAS_RVA: u16 = 0x0100;
const METHOD_ABSTRACT: u16 = 0x0400;
const METHOD_SPECIAL_NAME: u16 = 0x0800;
const METHOD_RT_SPECIAL_NAME: u16 = 0x1000;
const METHOD_PINVOKE_IMPL: u16 = 0x2000;
const METHOD_IMPL_CODE_TYPE_MASK: u16 = 0x0003;
const METHOD_IMPL_UNMANAGED: u16 = 0x0004;
const METHOD_IMPL_FORWARD_REF: u16 = 0x0010;
const METHOD_IMPL_INTERNAL_CALL: u16 = 0x1000;

const CCTOR_PATTERN: [&str; 34] = [
    "ldc",
    "newarr",
    "stsfld",
    "ldc",
    "newarr",
    "dup",
    "ldtoken",
    "call",
    "stsfld",
    "ldc",
    "stloc.0",
    "br",
    "ldsfld",
    "ldloc.0",
    "ldsfld",
    "ldloc.0",
    "ldelem.u1",
    "ldloc.0",
    "xor",
    "ldc",
    "xor",
    "conv.u1",
    "stelem.i1",
    "ldloc.0",
    "ldc",
    "add",
    "stloc.0",
    "ldloc.0",
    "ldsfld",
    "ldlen",
    "conv.i4",
    "clt",
    "brtrue",
    "ret",
];

const GETTER_PATTERN: [&str; 12] = [
    "call",
    "ldsfld",
    "ldarg.1",
    "ldarg.2",
    "callvirt",
    "stloc.0",
    "ldsfld",
    "ldarg.0",
    "ldloc.0",
    "stelem.ref",
    "ldloc.0",
    "ret",
];

const ACCESSOR_PATTERN: [&str; 11] = [
    "ldsfld",
    "ldc",
    "ldelem.ref",
    "dup",
    "brtrue",
    "pop",
    "ldc",
    "ldc",
    "ldc",
    "call",
    "ret",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObfuscarStringRecovery {
    pub carrier_count: u32,
    pub accessor_count: u32,
    pub recovered: Vec<RecoveredString>,
    pub unknown_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanFailure {
    ImageLimit,
    Metadata,
    TableLimit,
    MethodBodies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObfuscarScanState {
    Validated,
    Rejected,
}

impl ScanFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ImageLimit => "image exceeds the bounded Obfuscar profile",
            Self::Metadata => "metadata needed for the structural proof is unavailable",
            Self::TableLimit => "metadata row count exceeds the bounded Obfuscar profile",
            Self::MethodBodies => "CIL body budget or parsing prevented a complete proof",
        }
    }
}

#[derive(Debug)]
struct ScanContext<'a> {
    image: &'a [u8],
    pe: PeImage,
    resolver: Resolver,
    model: AssemblyModel,
    blob: Vec<u8>,
    init_array_tokens: BTreeSet<u32>,
    bodies: BTreeMap<u32, Arc<MethodBody>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConstructorProof {
    method_token: u32,
    cache_field: u32,
    data_field: u32,
    source_field: u32,
    cache_len: usize,
    data_len: usize,
    xor_key: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GetterProof {
    method_token: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AccessorProof {
    method_token: u32,
    method_name: String,
    cache_index: usize,
    start: usize,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompleteCarrier {
    accessor_count: u32,
    recovered: Vec<RecoveredString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CarrierScan {
    NoMatch,
    Incomplete,
    Complete(CompleteCarrier),
}

#[must_use]
pub fn recover_obfuscar_strings(image: &[u8]) -> ObfuscarStringRecovery {
    recover_obfuscar_strings_with_state(image).0
}

pub(crate) fn recover_obfuscar_strings_with_state(
    image: &[u8],
) -> (ObfuscarStringRecovery, ObfuscarScanState) {
    let context: ScanContext<'_> = match build_context(image) {
        Ok(context) => context,
        Err(failure) => {
            return (unknown(0, failure.as_str()), ObfuscarScanState::Rejected);
        }
    };
    let recovery: ObfuscarStringRecovery = aggregate_carrier_scans(
        context
            .model
            .types
            .iter()
            .map(|ty: &TypeModel| scan_carrier(&context, ty)),
    );
    (recovery, ObfuscarScanState::Validated)
}

fn aggregate_carrier_scans<I>(scans: I) -> ObfuscarStringRecovery
where
    I: IntoIterator<Item = CarrierScan>,
{
    let mut complete: Option<CompleteCarrier> = None;
    let mut carrier_count: u32 = 0;
    let mut incomplete_count: u32 = 0;
    for scan in scans {
        match scan {
            CarrierScan::NoMatch => {}
            CarrierScan::Incomplete => {
                incomplete_count = incomplete_count.saturating_add(1);
            }
            CarrierScan::Complete(carrier) => {
                carrier_count = carrier_count.saturating_add(1);
                if complete.is_none() {
                    complete = Some(carrier);
                }
            }
        }
    }
    if incomplete_count != 0 {
        return unknown(
            carrier_count,
            "a recognized Obfuscar StringSqueeze FieldRVA carrier graph was incomplete or unsupported",
        );
    }
    if carrier_count > 1 {
        return unknown(
            carrier_count,
            "multiple complete Obfuscar StringSqueeze FieldRVA carrier graphs are ambiguous",
        );
    }
    let Some(carrier): Option<CompleteCarrier> = complete else {
        return unknown(
            0,
            "no complete Obfuscar StringSqueeze FieldRVA carrier graph was found",
        );
    };
    ObfuscarStringRecovery {
        carrier_count,
        accessor_count: carrier.accessor_count,
        recovered: carrier.recovered,
        unknown_reason: None,
    }
}

fn unknown(carrier_count: u32, reason: &str) -> ObfuscarStringRecovery {
    ObfuscarStringRecovery {
        carrier_count,
        accessor_count: 0,
        recovered: Vec::new(),
        unknown_reason: Some(reason.to_owned()),
    }
}

fn build_context(image: &[u8]) -> std::result::Result<ScanContext<'_>, ScanFailure> {
    if image.len() > MAX_IMAGE_BYTES {
        return Err(ScanFailure::ImageLimit);
    }
    let pe: PeImage = parse(image).map_err(|_| ScanFailure::Metadata)?;
    validate_section_map(image, &pe)?;
    let clr_directory: DataDirectory = pe.clr_directory().ok_or(ScanFailure::Metadata)?;
    let clr_size: usize =
        usize::try_from(clr_directory.size.max(72)).map_err(|_| ScanFailure::Metadata)?;
    file_backed_tail(image, &pe, clr_directory.rva)
        .and_then(|bytes: &[u8]| bytes.get(..clr_size))
        .ok_or(ScanFailure::Metadata)?;
    let clr: ClrHeader = parse_clr_header(image, &pe).map_err(|_| ScanFailure::Metadata)?;
    let metadata_size: usize =
        usize::try_from(clr.metadata.size).map_err(|_| ScanFailure::Metadata)?;
    if metadata_size > MAX_METADATA_BYTES {
        return Err(ScanFailure::ImageLimit);
    }
    let metadata: &[u8] = file_backed_tail(image, &pe, clr.metadata.rva)
        .and_then(|bytes: &[u8]| bytes.get(..metadata_size))
        .ok_or(ScanFailure::Metadata)?;
    let root: MetadataRoot =
        parse_metadata_root(image, &pe, &clr).map_err(|_| ScanFailure::Metadata)?;
    let table_header: StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or(ScanFailure::Metadata)?;
    let table_stream: TableStream =
        parse_table_stream(metadata, table_header).map_err(|_| ScanFailure::Metadata)?;
    preflight_table_counts(&table_stream)?;
    let blob_header: StreamHeader = root
        .streams
        .get("#Blob")
        .copied()
        .ok_or(ScanFailure::Metadata)?;
    let blob_start: usize =
        usize::try_from(blob_header.offset).map_err(|_| ScanFailure::Metadata)?;
    let blob_size: usize = usize::try_from(blob_header.size).map_err(|_| ScanFailure::Metadata)?;
    if blob_size > MAX_METADATA_BLOB_BYTES {
        return Err(ScanFailure::ImageLimit);
    }
    let blob_end: usize = blob_start
        .checked_add(blob_size)
        .ok_or(ScanFailure::Metadata)?;
    let blob: Vec<u8> = metadata
        .get(blob_start..blob_end)
        .ok_or(ScanFailure::Metadata)?
        .to_vec();
    let resolver: Resolver =
        Resolver::build(image, &pe, &clr, &root).map_err(|_| ScanFailure::Metadata)?;
    preflight_model_materialization(&resolver)?;
    let model: AssemblyModel = resolver.model();
    if model.type_count > MAX_TYPE_ROWS
        || model.method_count > MAX_METHOD_ROWS
        || model.field_count > MAX_FIELD_ROWS
    {
        return Err(ScanFailure::TableLimit);
    }
    let init_array_tokens: BTreeSet<u32> = init_array_tokens(&resolver, &blob);
    let bodies: BTreeMap<u32, Arc<MethodBody>> = read_bodies(image, &pe, &model)?;
    Ok(ScanContext {
        image,
        pe,
        resolver,
        model,
        blob,
        init_array_tokens,
        bodies,
    })
}

fn preflight_model_materialization(resolver: &Resolver) -> std::result::Result<(), ScanFailure> {
    let tables: &crate::tables::Tables = resolver.tables();
    let mut signature_bytes: usize = 0;
    for signature in tables
        .methods
        .iter()
        .map(|row| row.signature)
        .chain(tables.fields.iter().map(|row| row.signature))
        .chain(tables.member_refs.iter().map(|row| row.signature))
        .chain(tables.standalone_sigs.iter().map(|row| row.signature))
        .chain(tables.type_specs.iter().map(|row| row.signature))
        .chain(tables.method_specs.iter().map(|row| row.instantiation))
    {
        let length: usize = resolver.blob(signature).ok_or(ScanFailure::Metadata)?.len();
        signature_bytes = signature_bytes
            .checked_add(length)
            .filter(|total: &usize| *total <= MAX_MODEL_SIGNATURE_BYTES)
            .ok_or(ScanFailure::TableLimit)?;
    }

    let mut name_bytes: usize = 0;
    for index in tables
        .modules
        .iter()
        .map(|row| row.name)
        .chain(
            tables
                .type_refs
                .iter()
                .flat_map(|row| [row.namespace, row.name]),
        )
        .chain(
            tables
                .type_defs
                .iter()
                .flat_map(|row| [row.namespace, row.name]),
        )
        .chain(tables.fields.iter().map(|row| row.name))
        .chain(tables.methods.iter().map(|row| row.name))
        .chain(tables.params.iter().map(|row| row.name))
        .chain(
            tables
                .assembly
                .iter()
                .flat_map(|row| [row.name, row.culture]),
        )
        .chain(
            tables
                .assembly_refs
                .iter()
                .flat_map(|row| [row.name, row.culture]),
        )
    {
        charge_name_bytes(&mut name_bytes, resolver, index)?;
    }
    for row in &tables.type_defs {
        let Some(base): Option<RowRef> = row.extends else {
            continue;
        };
        let index: usize = usize::try_from(base.row.checked_sub(1).ok_or(ScanFailure::Metadata)?)
            .map_err(|_| ScanFailure::Metadata)?;
        let indices: [u32; 2] = match base.table {
            TableId::TypeDef => {
                let target: &crate::tables::TypeDefRow =
                    tables.type_defs.get(index).ok_or(ScanFailure::Metadata)?;
                [target.namespace, target.name]
            }
            TableId::TypeRef => {
                let target: &crate::tables::TypeRefRow =
                    tables.type_refs.get(index).ok_or(ScanFailure::Metadata)?;
                [target.namespace, target.name]
            }
            _ => return Err(ScanFailure::TableLimit),
        };
        for name_index in indices {
            charge_name_bytes(&mut name_bytes, resolver, name_index)?;
        }
    }
    Ok(())
}

fn charge_name_bytes(
    total: &mut usize,
    resolver: &Resolver,
    index: u32,
) -> std::result::Result<(), ScanFailure> {
    let length: usize = resolver.string_len(index).ok_or(ScanFailure::Metadata)?;
    *total = (*total)
        .checked_add(length)
        .filter(|value: &usize| *value <= MAX_MODEL_NAME_BYTES)
        .ok_or(ScanFailure::TableLimit)?;
    Ok(())
}

fn validate_section_map(image: &[u8], pe: &PeImage) -> std::result::Result<(), ScanFailure> {
    let image_len: u64 = u64::try_from(image.len()).map_err(|_| ScanFailure::ImageLimit)?;
    let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(pe.sections.len());
    for section in &pe.sections {
        let raw_start: u64 = u64::from(section.raw_pointer);
        let raw_end: u64 = raw_start
            .checked_add(u64::from(section.raw_size))
            .ok_or(ScanFailure::Metadata)?;
        if raw_end > image_len {
            return Err(ScanFailure::Metadata);
        }
        let mapped_size: u64 = u64::from(section.virtual_size.max(section.raw_size));
        if mapped_size == 0 {
            continue;
        }
        let mapped_start: u64 = u64::from(section.virtual_address);
        let mapped_end: u64 = mapped_start
            .checked_add(mapped_size)
            .ok_or(ScanFailure::Metadata)?;
        ranges.push((mapped_start, mapped_end));
    }
    ranges.sort_unstable();
    if ranges
        .windows(2)
        .any(|pair: &[(u64, u64)]| pair[0].1 > pair[1].0)
    {
        return Err(ScanFailure::Metadata);
    }
    Ok(())
}

fn file_backed_tail<'a>(image: &'a [u8], pe: &PeImage, rva: u32) -> Option<&'a [u8]> {
    let section: &SectionHeader = pe.sections.iter().find(|section| {
        let start: u64 = u64::from(section.virtual_address);
        let address: u64 = u64::from(rva);
        address >= start && address - start < u64::from(section.raw_size)
    })?;
    let delta: u64 = u64::from(rva).checked_sub(u64::from(section.virtual_address))?;
    let offset: usize = usize::try_from(u64::from(section.raw_pointer).checked_add(delta)?).ok()?;
    let available: usize = usize::try_from(u64::from(section.raw_size).checked_sub(delta)?).ok()?;
    let end: usize = offset.checked_add(available)?;
    image.get(offset..end)
}

fn preflight_table_counts(table_stream: &TableStream) -> std::result::Result<(), ScanFailure> {
    let total_rows: u64 = table_stream
        .row_counts
        .values()
        .try_fold(0u64, |total: u64, count: &u32| {
            total.checked_add(u64::from(*count))
        })
        .ok_or(ScanFailure::TableLimit)?;
    if total_rows > MAX_TOTAL_TABLE_ROWS
        || table_row_count(table_stream, TableId::TypeDef) > MAX_TYPE_ROWS
        || table_row_count(table_stream, TableId::MethodDef) > MAX_METHOD_ROWS
        || table_row_count(table_stream, TableId::Field) > MAX_FIELD_ROWS
        || table_row_count(table_stream, TableId::MemberRef) > MAX_MEMBER_REF_ROWS
    {
        return Err(ScanFailure::TableLimit);
    }
    Ok(())
}

fn table_row_count(table_stream: &TableStream, table: TableId) -> u32 {
    table_stream
        .row_counts
        .get(&table.index())
        .copied()
        .unwrap_or(0)
}

fn read_bodies(
    image: &[u8],
    pe: &PeImage,
    model: &AssemblyModel,
) -> std::result::Result<BTreeMap<u32, Arc<MethodBody>>, ScanFailure> {
    let mut total_code: usize = 0;
    let mut total_parse_bytes: usize = 0;
    let mut total_instructions: usize = 0;
    let mut total_exception_clauses: usize = 0;
    let mut bodies: BTreeMap<u32, Arc<MethodBody>> = BTreeMap::new();
    let mut bodies_by_rva: BTreeMap<u32, Arc<MethodBody>> = BTreeMap::new();
    for method in model.types.iter().flat_map(|ty: &TypeModel| &ty.methods) {
        if method.rva == 0 {
            continue;
        }
        let cached_body: Option<&Arc<MethodBody>> = bodies_by_rva.get(&method.rva);
        if let Some(body) = cached_body {
            if bodies.insert(method.token, Arc::clone(body)).is_some() {
                return Err(ScanFailure::MethodBodies);
            }
            continue;
        }
        let bytes: &[u8] =
            file_backed_tail(image, pe, method.rva).ok_or(ScanFailure::MethodBodies)?;
        let declared_size: u32 =
            method_body_code_size(bytes).map_err(|_| ScanFailure::MethodBodies)?;
        if declared_size > MAX_METHOD_CODE {
            return Err(ScanFailure::MethodBodies);
        }
        let code_size: usize =
            usize::try_from(declared_size).map_err(|_| ScanFailure::MethodBodies)?;
        total_code = total_code
            .checked_add(code_size)
            .filter(|total: &usize| *total <= MAX_TOTAL_METHOD_CODE)
            .ok_or(ScanFailure::MethodBodies)?;
        let parse_end: usize = bytes.len().min(MAX_METHOD_PARSE_BYTES);
        let extent: MethodBodyExtent =
            method_body_extent(&bytes[..parse_end]).map_err(|_| ScanFailure::MethodBodies)?;
        if extent.code_size != declared_size {
            return Err(ScanFailure::MethodBodies);
        }
        total_parse_bytes = total_parse_bytes
            .checked_add(extent.consumed_bytes)
            .filter(|total: &usize| *total <= MAX_TOTAL_PARSE_BYTES)
            .ok_or(ScanFailure::MethodBodies)?;
        let body: MethodBody = parse_method_body(&bytes[..extent.consumed_bytes])
            .map_err(|_| ScanFailure::MethodBodies)?;
        total_instructions = total_instructions
            .checked_add(body.instructions.len())
            .filter(|total: &usize| *total <= MAX_TOTAL_INSTRUCTIONS)
            .ok_or(ScanFailure::MethodBodies)?;
        total_exception_clauses = total_exception_clauses
            .checked_add(body.exception_clauses.len())
            .filter(|total: &usize| *total <= MAX_TOTAL_EXCEPTION_CLAUSES)
            .ok_or(ScanFailure::MethodBodies)?;
        let body: Arc<MethodBody> = Arc::new(body);
        if bodies_by_rva
            .insert(method.rva, Arc::clone(&body))
            .is_some()
            || bodies.insert(method.token, body).is_some()
        {
            return Err(ScanFailure::MethodBodies);
        }
    }
    Ok(bodies)
}

fn scan_carrier(context: &ScanContext<'_>, ty: &TypeModel) -> CarrierScan {
    if !has_carrier_shape(context, ty) {
        return CarrierScan::NoMatch;
    }
    prove_carrier(context, ty).map_or(CarrierScan::Incomplete, CarrierScan::Complete)
}

fn has_carrier_shape(context: &ScanContext<'_>, ty: &TypeModel) -> bool {
    let source_fields: BTreeSet<u32> = ty
        .fields
        .iter()
        .filter(|field: &&FieldModel| {
            field.flags & (FIELD_STATIC | FIELD_HAS_RVA) == (FIELD_STATIC | FIELD_HAS_RVA)
        })
        .map(|field: &FieldModel| field.token)
        .collect();
    let data_fields: BTreeSet<u32> = ty
        .fields
        .iter()
        .filter(|field: &&FieldModel| {
            field.flags & FIELD_STATIC != 0
                && matches!(field.field_type, TypeSig::SzArray(ref inner) if matches!(inner.as_ref(), TypeSig::U1))
        })
        .map(|field: &FieldModel| field.token)
        .collect();
    let cache_fields: BTreeSet<u32> = ty
        .fields
        .iter()
        .filter(|field: &&FieldModel| {
            field.flags & FIELD_STATIC != 0
                && matches!(field.field_type, TypeSig::SzArray(ref inner) if matches!(inner.as_ref(), TypeSig::String))
        })
        .map(|field: &FieldModel| field.token)
        .collect();
    if source_fields.is_empty() || data_fields.is_empty() || cache_fields.is_empty() {
        return false;
    }
    ty.methods.iter().any(|method: &MethodModel| {
        if method.name != ".cctor" {
            return false;
        }
        context
            .bodies
            .get(&method.token)
            .map(Arc::as_ref)
            .is_some_and(|body: &MethodBody| {
            let has_initialize_array: bool = body.instructions.iter().any(|instruction: &Instruction| {
                instruction.name == "call"
                    && matches!(instruction.operand, OperandValue::Token(token) if context.init_array_tokens.contains(&token))
            });
            let has_source: bool = body.instructions.iter().any(|instruction: &Instruction| {
                instruction.name == "ldtoken"
                    && matches!(instruction.operand, OperandValue::Token(token) if source_fields.contains(&token))
            });
            let has_data: bool = body.instructions.iter().any(|instruction: &Instruction| {
                instruction.name == "stsfld"
                    && matches!(instruction.operand, OperandValue::Token(token) if data_fields.contains(&token))
            });
            let has_cache: bool = body.instructions.iter().any(|instruction: &Instruction| {
                instruction.name == "stsfld"
                    && matches!(instruction.operand, OperandValue::Token(token) if cache_fields.contains(&token))
            });
            has_initialize_array && has_source && has_data && has_cache
            })
    })
}

fn prove_carrier(context: &ScanContext<'_>, ty: &TypeModel) -> Option<CompleteCarrier> {
    let mut constructor: Option<ConstructorProof> = None;
    for method in &ty.methods {
        if method.name != ".cctor" {
            continue;
        }
        let body: &MethodBody = context.bodies.get(&method.token)?.as_ref();
        let Some(proof): Option<ConstructorProof> = prove_constructor(context, ty, method, body)
        else {
            continue;
        };
        if constructor.replace(proof).is_some() {
            return None;
        }
    }
    let constructor: ConstructorProof = constructor?;
    let data: Vec<u8> = recover_field_data(context, ty, constructor)?;
    let getter: GetterProof = prove_unique_getter(context, ty, constructor)?;
    let recovered: Vec<RecoveredString> = prove_accessors(context, ty, constructor, getter, &data)?;
    Some(CompleteCarrier {
        accessor_count: u32::try_from(constructor.cache_len).ok()?,
        recovered,
    })
}

fn prove_constructor(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    method: &MethodModel,
    body: &MethodBody,
) -> Option<ConstructorProof> {
    if !is_type_initializer(method)
        || !has_exact_method_signature(&context.resolver, method)
        || body.code_size > MAX_CONSTRUCTOR_CODE
        || body.instructions.len() > MAX_CONSTRUCTOR_INSTRUCTIONS
        || body.max_stack > MAX_STACK
        || !body.exception_clauses.is_empty()
        || !has_exact_locals(&context.resolver, body, &["int"])
    {
        return None;
    }
    let instructions: Vec<&Instruction> = semantic_instructions(body);
    if !matches_pattern(&instructions, &CCTOR_PATTERN) {
        return None;
    }
    let cache_len: usize = nonnegative_usize(instructions.first().copied()?)?;
    let data_len: usize = nonnegative_usize(*instructions.get(3)?)?;
    let xor_key: u8 = u8::try_from(int_immediate(instructions.get(19)?)?).ok()?;
    if cache_len == 0
        || cache_len > MAX_ACCESSORS
        || data_len == 0
        || data_len > MAX_FIELD_DATA
        || int_immediate(instructions.get(9)?)? != 0
        || int_immediate(instructions.get(24)?)? != 1
    {
        return None;
    }
    if !is_corelib_type_token(
        &context.resolver,
        &context.blob,
        token(instructions.get(1)?, "newarr")?,
        "System",
        "String",
    ) || !is_corelib_type_token(
        &context.resolver,
        &context.blob,
        token(instructions.get(4)?, "newarr")?,
        "System",
        "Byte",
    ) {
        return None;
    }
    let cache_field: u32 = token(instructions.get(2)?, "stsfld")?;
    let source_field: u32 = token(instructions.get(6)?, "ldtoken")?;
    let initialize_array: u32 = token(instructions.get(7)?, "call")?;
    let data_field: u32 = token(instructions.get(8)?, "stsfld")?;
    let owned_fields: BTreeSet<u32> = ty
        .fields
        .iter()
        .map(|field: &FieldModel| field.token)
        .collect();
    if !owned_fields.contains(&cache_field)
        || !owned_fields.contains(&source_field)
        || !owned_fields.contains(&data_field)
        || !context.init_array_tokens.contains(&initialize_array)
        || token(instructions.get(12)?, "ldsfld")? != data_field
        || token(instructions.get(14)?, "ldsfld")? != data_field
        || token(instructions.get(28)?, "ldsfld")? != data_field
        || !branch_reaches(body, instructions.get(11)?, instructions.get(27)?)
        || !branch_reaches(body, instructions.get(32)?, instructions.get(12)?)
    {
        return None;
    }
    Some(ConstructorProof {
        method_token: method.token,
        cache_field,
        data_field,
        source_field,
        cache_len,
        data_len,
        xor_key,
    })
}

fn recover_field_data(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    proof: ConstructorProof,
) -> Option<Vec<u8>> {
    let source: &FieldModel = field(ty, proof.source_field)?;
    let data: &FieldModel = field(ty, proof.data_field)?;
    let cache: &FieldModel = field(ty, proof.cache_field)?;
    if source.flags & (FIELD_STATIC | FIELD_HAS_RVA) != (FIELD_STATIC | FIELD_HAS_RVA)
        || data.flags & FIELD_STATIC == 0
        || cache.flags & FIELD_STATIC == 0
        || !matches!(data.field_type, TypeSig::SzArray(ref inner) if matches!(inner.as_ref(), TypeSig::U1))
        || !matches!(cache.field_type, TypeSig::SzArray(ref inner) if matches!(inner.as_ref(), TypeSig::String))
    {
        return None;
    }
    let TypeSig::NamedType {
        is_value_type: true,
        token: source_type,
    } = source.field_type
    else {
        return None;
    };
    if source_type >> 24 != u32::from(TableId::TypeDef as u8) {
        return None;
    }
    let source_type_rid: u32 = source_type & 0x00FF_FFFF;
    let owner_rid: u32 = ty.token & 0x00FF_FFFF;
    if unique_nested_owner(&context.resolver, source_type_rid)? != owner_rid {
        return None;
    }
    let class_size: u32 = unique_class_size(&context.resolver, source_type_rid)?;
    if usize::try_from(class_size).ok()? != proof.data_len {
        return None;
    }
    let field_rva: u32 = unique_field_rva(&context.resolver, proof.source_field)?;
    let raw: &[u8] =
        file_backed_tail(context.image, &context.pe, field_rva)?.get(..proof.data_len)?;
    let mut recovered: Vec<u8> = Vec::with_capacity(proof.data_len);
    for (index, byte) in raw.iter().copied().enumerate() {
        recovered.push(byte ^ index.to_le_bytes()[0] ^ proof.xor_key);
    }
    Some(recovered)
}

fn prove_unique_getter(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    constructor: ConstructorProof,
) -> Option<GetterProof> {
    let mut getter: Option<GetterProof> = None;
    for method in &ty.methods {
        let Some(body): Option<&MethodBody> = context.bodies.get(&method.token).map(Arc::as_ref)
        else {
            continue;
        };
        let Some(proof): Option<GetterProof> = prove_getter(context, method, body, constructor)
        else {
            continue;
        };
        if getter.replace(proof).is_some() {
            return None;
        }
    }
    getter
}

fn prove_getter(
    context: &ScanContext<'_>,
    method: &MethodModel,
    body: &MethodBody,
    constructor: ConstructorProof,
) -> Option<GetterProof> {
    if !is_static_string_getter(method)
        || !has_exact_method_signature(&context.resolver, method)
        || body.code_size > MAX_GETTER_CODE
        || body.instructions.len() > MAX_GETTER_INSTRUCTIONS
        || body.max_stack > MAX_STACK
        || !body.exception_clauses.is_empty()
        || !has_exact_locals(&context.resolver, body, &["string"])
    {
        return None;
    }
    let instructions: Vec<&Instruction> = semantic_instructions(body);
    if !matches_pattern(&instructions, &GETTER_PATTERN)
        || token(instructions.get(1)?, "ldsfld")? != constructor.data_field
        || token(instructions.get(6)?, "ldsfld")? != constructor.cache_field
        || !is_encoding_get_utf8(
            &context.resolver,
            &context.blob,
            token(instructions.first().copied()?, "call")?,
        )
        || !is_encoding_get_string(
            &context.resolver,
            &context.blob,
            token(instructions.get(4)?, "callvirt")?,
        )
    {
        return None;
    }
    Some(GetterProof {
        method_token: method.token,
    })
}

fn prove_accessors(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    constructor: ConstructorProof,
    getter: GetterProof,
    data: &[u8],
) -> Option<Vec<RecoveredString>> {
    let mut accessors: BTreeMap<usize, AccessorProof> = BTreeMap::new();
    for method in &ty.methods {
        let Some(body): Option<&MethodBody> = context.bodies.get(&method.token).map(Arc::as_ref)
        else {
            continue;
        };
        let getter_refs: usize = body
            .instructions
            .iter()
            .filter(|instruction: &&Instruction| {
                instruction.operand == OperandValue::Token(getter.method_token)
            })
            .count();
        if getter_refs == 0 {
            continue;
        }
        if getter_refs != 1 {
            return None;
        }
        let proof: AccessorProof =
            prove_accessor(&context.resolver, method, body, constructor, getter)?;
        let index: usize = proof.cache_index;
        if accessors.insert(index, proof).is_some() {
            return None;
        }
    }
    if accessors.len() != constructor.cache_len {
        return None;
    }
    let accessor_tokens: BTreeSet<u32> = accessors
        .values()
        .map(|accessor: &AccessorProof| accessor.method_token)
        .collect();
    if !validate_reference_scope(context, ty, constructor, getter, &accessor_tokens) {
        return None;
    }
    let mut cursor: usize = 0;
    let mut recovered_name_bytes: usize = 0;
    let mut recovered: Vec<RecoveredString> = Vec::with_capacity(accessors.len());
    for index in 0..constructor.cache_len {
        let accessor: &AccessorProof = accessors.get(&index)?;
        if accessor.start != cursor || accessor.count > MAX_STRING_BYTES {
            return None;
        }
        let end: usize = accessor.start.checked_add(accessor.count)?;
        let bytes: &[u8] = data.get(accessor.start..end)?;
        let text: String = std::str::from_utf8(bytes).ok()?.to_owned();
        cursor = end;
        if cursor > MAX_RECOVERED_BYTES {
            return None;
        }
        let method_name_bytes: usize = ty
            .full_name
            .len()
            .checked_add(2)?
            .checked_add(accessor.method_name.len())?;
        recovered_name_bytes = recovered_name_bytes
            .checked_add(method_name_bytes)
            .filter(|total: &usize| *total <= MAX_RECOVERED_NAME_BYTES)?;
        recovered.push(RecoveredString {
            method_token: accessor.method_token,
            method_name: format!("{}::{}", ty.full_name, accessor.method_name),
            text,
        });
    }
    (cursor == data.len()).then_some(recovered)
}

fn prove_accessor(
    resolver: &Resolver,
    method: &MethodModel,
    body: &MethodBody,
    constructor: ConstructorProof,
    getter: GetterProof,
) -> Option<AccessorProof> {
    if !is_static_string_accessor(method)
        || !has_exact_method_signature(resolver, method)
        || body.code_size > MAX_ACCESSOR_CODE
        || body.instructions.len() > MAX_ACCESSOR_INSTRUCTIONS
        || body.max_stack > MAX_STACK
        || !body.exception_clauses.is_empty()
    {
        return None;
    }
    let instructions: Vec<&Instruction> = semantic_instructions(body);
    if !matches_pattern(&instructions, &ACCESSOR_PATTERN)
        || token(instructions.first().copied()?, "ldsfld")? != constructor.cache_field
        || token(instructions.get(9)?, "call")? != getter.method_token
        || !branch_reaches(body, instructions.get(4)?, instructions.get(10)?)
    {
        return None;
    }
    let cached_index: usize = nonnegative_usize(*instructions.get(1)?)?;
    let call_index: usize = nonnegative_usize(*instructions.get(6)?)?;
    let start: usize = nonnegative_usize(*instructions.get(7)?)?;
    let count: usize = nonnegative_usize(*instructions.get(8)?)?;
    if cached_index != call_index || cached_index >= constructor.cache_len {
        return None;
    }
    Some(AccessorProof {
        method_token: method.token,
        method_name: method.name.clone(),
        cache_index: cached_index,
        start,
        count,
    })
}

fn validate_reference_scope(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    constructor: ConstructorProof,
    getter: GetterProof,
    accessors: &BTreeSet<u32>,
) -> bool {
    let Some(aliases): Option<BTreeSet<u32>> =
        protected_member_aliases(context, ty, constructor, getter)
    else {
        return false;
    };
    for (method_token, body) in &context.bodies {
        for instruction in &body.instructions {
            let OperandValue::Token(referenced) = instruction.operand else {
                continue;
            };
            if aliases.contains(&referenced) {
                return false;
            }
            if referenced == constructor.source_field
                && !(*method_token == constructor.method_token && instruction.name == "ldtoken")
            {
                return false;
            }
            if referenced == constructor.data_field {
                let constructor_access: bool = *method_token == constructor.method_token
                    && matches!(instruction.name.as_str(), "ldsfld" | "stsfld");
                let getter_access: bool =
                    *method_token == getter.method_token && instruction.name == "ldsfld";
                if !constructor_access && !getter_access {
                    return false;
                }
            }
            if referenced == constructor.cache_field {
                let constructor_access: bool =
                    *method_token == constructor.method_token && instruction.name == "stsfld";
                let getter_access: bool =
                    *method_token == getter.method_token && instruction.name == "ldsfld";
                let accessor_access: bool =
                    accessors.contains(method_token) && instruction.name == "ldsfld";
                if !constructor_access && !getter_access && !accessor_access {
                    return false;
                }
            }
            if referenced == getter.method_token
                && !(accessors.contains(method_token) && instruction.name == "call")
            {
                return false;
            }
        }
    }
    true
}

fn protected_member_aliases(
    context: &ScanContext<'_>,
    ty: &TypeModel,
    constructor: ConstructorProof,
    getter: GetterProof,
) -> Option<BTreeSet<u32>> {
    let getter_name: &str = ty
        .methods
        .iter()
        .find(|method: &&MethodModel| method.token == getter.method_token)?
        .name
        .as_str();
    let member_names: [&str; 4] = [
        field(ty, constructor.source_field)?.name.as_str(),
        field(ty, constructor.data_field)?.name.as_str(),
        field(ty, constructor.cache_field)?.name.as_str(),
        getter_name,
    ];
    let qualified: BTreeSet<String> = member_names
        .iter()
        .map(|name: &&str| format!("{}::{name}", ty.full_name))
        .collect();
    let mut aliases: BTreeSet<u32> = BTreeSet::new();
    for (index, _) in context.resolver.tables().member_refs.iter().enumerate() {
        let rid: u32 = u32::try_from(index).ok()?.checked_add(1)?;
        let token: u32 = (u32::from(TableId::MemberRef.index()) << 24) | rid;
        if qualified.contains(&context.resolver.resolve_token(token)) {
            aliases.insert(token);
        }
    }
    Some(aliases)
}

fn field(ty: &TypeModel, token: u32) -> Option<&FieldModel> {
    ty.fields
        .iter()
        .find(|field: &&FieldModel| field.token == token)
}

fn unique_nested_owner(resolver: &Resolver, nested_rid: u32) -> Option<u32> {
    let mut owner: Option<u32> = None;
    for row in &resolver.tables().nested_classes {
        if row.nested_class == nested_rid && owner.replace(row.enclosing_class).is_some() {
            return None;
        }
    }
    owner
}

fn unique_class_size(resolver: &Resolver, type_rid: u32) -> Option<u32> {
    let mut class_size: Option<u32> = None;
    for row in &resolver.tables().class_layouts {
        if row.parent != type_rid {
            continue;
        }
        if row.packing_size != 1 || class_size.replace(row.class_size).is_some() {
            return None;
        }
    }
    class_size
}

fn unique_field_rva(resolver: &Resolver, field_token: u32) -> Option<u32> {
    if field_token >> 24 != u32::from(TableId::Field as u8) {
        return None;
    }
    let field_rid: u32 = field_token & 0x00FF_FFFF;
    let mut rva: Option<u32> = None;
    for row in &resolver.tables().field_rvas {
        if row.field == field_rid && rva.replace(row.rva).is_some() {
            return None;
        }
    }
    rva
}

const fn is_static_void(method: &MethodModel) -> bool {
    method.is_static()
        && method.signature.calling_convention == SIG_DEFAULT
        && !method.signature.has_this
        && !method.signature.explicit_this
        && method.signature.generic_param_count == 0
        && method.signature.params.is_empty()
        && matches!(method.signature.return_type, TypeSigOrVoid::Void)
}

const fn is_managed_il(method: &MethodModel) -> bool {
    method.rva != 0
        && method.flags & (METHOD_ABSTRACT | METHOD_PINVOKE_IMPL) == 0
        && method.impl_flags
            & (METHOD_IMPL_CODE_TYPE_MASK
                | METHOD_IMPL_UNMANAGED
                | METHOD_IMPL_FORWARD_REF
                | METHOD_IMPL_INTERNAL_CALL)
            == 0
}

const fn is_type_initializer(method: &MethodModel) -> bool {
    is_static_void(method)
        && is_managed_il(method)
        && method.flags & (METHOD_SPECIAL_NAME | METHOD_RT_SPECIAL_NAME)
            == (METHOD_SPECIAL_NAME | METHOD_RT_SPECIAL_NAME)
}

fn is_static_string_getter(method: &MethodModel) -> bool {
    method.is_static()
        && is_managed_il(method)
        && method.signature.calling_convention == SIG_DEFAULT
        && !method.signature.has_this
        && !method.signature.explicit_this
        && method.signature.generic_param_count == 0
        && method.signature.params == [TypeSig::I4, TypeSig::I4, TypeSig::I4]
        && matches!(
            method.signature.return_type,
            TypeSigOrVoid::Type(TypeSig::String)
        )
}

const fn is_static_string_accessor(method: &MethodModel) -> bool {
    method.is_static()
        && is_managed_il(method)
        && method.signature.calling_convention == SIG_DEFAULT
        && !method.signature.has_this
        && !method.signature.explicit_this
        && method.signature.generic_param_count == 0
        && method.signature.params.is_empty()
        && matches!(
            method.signature.return_type,
            TypeSigOrVoid::Type(TypeSig::String)
        )
}

fn is_encoding_get_utf8(resolver: &Resolver, blob: &[u8], token: u32) -> bool {
    if !is_corelib_member_ref(resolver, blob, token, "System.Text", "Encoding", "get_UTF8") {
        return false;
    }
    let Some(signature) = resolver.callee_signature(token) else {
        return false;
    };
    let TypeSigOrVoid::Type(TypeSig::NamedType {
        is_value_type: false,
        token: return_token,
    }) = signature.return_type
    else {
        return false;
    };
    signature.calling_convention == SIG_DEFAULT
        && !signature.has_this
        && !signature.explicit_this
        && signature.generic_param_count == 0
        && signature.params.is_empty()
        && is_corelib_type_token(resolver, blob, return_token, "System.Text", "Encoding")
}

fn is_encoding_get_string(resolver: &Resolver, blob: &[u8], token: u32) -> bool {
    if !is_corelib_member_ref(
        resolver,
        blob,
        token,
        "System.Text",
        "Encoding",
        "GetString",
    ) {
        return false;
    }
    let Some(signature) = resolver.callee_signature(token) else {
        return false;
    };
    signature.calling_convention == (SIG_HASTHIS | SIG_DEFAULT)
        && signature.has_this
        && !signature.explicit_this
        && signature.generic_param_count == 0
        && signature.params
            == [
                TypeSig::SzArray(Box::new(TypeSig::U1)),
                TypeSig::I4,
                TypeSig::I4,
            ]
        && matches!(signature.return_type, TypeSigOrVoid::Type(TypeSig::String))
}

fn is_corelib_member_ref(
    resolver: &Resolver,
    blob: &[u8],
    token: u32,
    namespace: &str,
    type_name: &str,
    member_name: &str,
) -> bool {
    if token >> 24 != u32::from(TableId::MemberRef as u8) {
        return false;
    }
    let rid: u32 = token & 0x00FF_FFFF;
    let Some(index): Option<usize> = rid
        .checked_sub(1)
        .and_then(|value: u32| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(row) = resolver.tables().member_refs.get(index) else {
        return false;
    };
    resolver.string(row.name) == member_name
        && row.parent.is_some_and(|parent: RowRef| {
            is_corelib_type_ref(resolver, blob, parent, namespace, type_name)
        })
}

fn is_corelib_type_token(
    resolver: &Resolver,
    blob: &[u8],
    token: u32,
    namespace: &str,
    name: &str,
) -> bool {
    if token >> 24 != u32::from(TableId::TypeRef as u8) {
        return false;
    }
    is_corelib_type_ref(
        resolver,
        blob,
        RowRef {
            table: TableId::TypeRef,
            row: token & 0x00FF_FFFF,
        },
        namespace,
        name,
    )
}

fn has_exact_locals(resolver: &Resolver, body: &MethodBody, expected: &[&str]) -> bool {
    let locals: Vec<String> = resolver.local_types(body.local_var_sig_tok, TargetLang::CSharp);
    locals
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn has_exact_method_signature(resolver: &Resolver, method: &MethodModel) -> bool {
    resolver
        .callee_signature(method.token)
        .is_some_and(|signature| signature == method.signature)
}

fn semantic_instructions(body: &MethodBody) -> Vec<&Instruction> {
    body.instructions
        .iter()
        .filter(|instruction: &&Instruction| instruction.name != "nop")
        .collect()
}

fn matches_pattern(instructions: &[&Instruction], pattern: &[&str]) -> bool {
    instructions.len() == pattern.len()
        && instructions.iter().zip(pattern).all(
            |(instruction, expected): (&&Instruction, &&str)| opcode_matches(instruction, expected),
        )
}

fn opcode_matches(instruction: &Instruction, expected: &str) -> bool {
    match expected {
        "ldc" => int_immediate(instruction).is_some(),
        "br" => matches!(instruction.name.as_str(), "br" | "br.s"),
        "brtrue" => matches!(instruction.name.as_str(), "brtrue" | "brtrue.s"),
        _ => instruction.name == expected,
    }
}

fn branch_reaches(body: &MethodBody, branch: &Instruction, target: &Instruction) -> bool {
    let OperandValue::BrTarget(relative) = branch.operand else {
        return false;
    };
    let Some(branch_index): Option<usize> = body
        .instructions
        .iter()
        .position(|instruction: &Instruction| instruction.offset == branch.offset)
    else {
        return false;
    };
    let Some(next): Option<&Instruction> = body.instructions.get(branch_index.saturating_add(1))
    else {
        return false;
    };
    let Some(raw_target): Option<i64> = i64::from(next.offset).checked_add(i64::from(relative))
    else {
        return false;
    };
    let Ok(raw_target): std::result::Result<u32, _> = u32::try_from(raw_target) else {
        return false;
    };
    let Some(mut target_index): Option<usize> = body
        .instructions
        .iter()
        .position(|instruction: &Instruction| instruction.offset == raw_target)
    else {
        return false;
    };
    while body
        .instructions
        .get(target_index)
        .is_some_and(|instruction: &Instruction| instruction.name == "nop")
    {
        target_index = target_index.saturating_add(1);
    }
    body.instructions
        .get(target_index)
        .is_some_and(|instruction: &Instruction| instruction.offset == target.offset)
}

fn token(instruction: &Instruction, opcode: &str) -> Option<u32> {
    if instruction.name != opcode {
        return None;
    }
    match instruction.operand {
        OperandValue::Token(token) => Some(token),
        _ => None,
    }
}

fn nonnegative_usize(instruction: &Instruction) -> Option<usize> {
    usize::try_from(int_immediate(instruction)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ParamModel;
    use crate::pe::PeBitness;
    use crate::signature::MethodSig;

    fn method(flags: u16, impl_flags: u16, rva: u32) -> MethodModel {
        MethodModel {
            token: 0x0600_0001,
            name: ".cctor".to_owned(),
            flags,
            impl_flags,
            rva,
            signature: MethodSig::default(),
            parameters: Vec::<ParamModel>::new(),
        }
    }

    #[test]
    fn method_flags_reject_non_il_initializers() {
        let valid_flags: u16 = 0x0010 | METHOD_SPECIAL_NAME | METHOD_RT_SPECIAL_NAME;
        assert!(is_type_initializer(&method(valid_flags, 0, 1)));
        assert!(!is_type_initializer(&method(valid_flags, 0x0001, 1)));
        assert!(!is_type_initializer(&method(
            valid_flags | METHOD_ABSTRACT,
            0,
            1,
        )));
        assert!(!is_type_initializer(&method(
            valid_flags | METHOD_PINVOKE_IMPL,
            0,
            1,
        )));
        assert!(!is_type_initializer(&method(valid_flags, 0, 0)));
    }

    #[test]
    fn section_map_rejects_overlapping_rva_ranges() {
        let pe: PeImage = PeImage {
            bitness: PeBitness::Pe32,
            machine: 0,
            number_of_sections: 2,
            timestamp: 0,
            characteristics: 0,
            entry_point_rva: 0,
            image_base: 0,
            data_directories: Vec::new(),
            sections: vec![
                SectionHeader {
                    name: "a".to_owned(),
                    virtual_size: 0x200,
                    virtual_address: 0x2000,
                    raw_size: 0x200,
                    raw_pointer: 0,
                    characteristics: 0,
                },
                SectionHeader {
                    name: "b".to_owned(),
                    virtual_size: 0x200,
                    virtual_address: 0x2100,
                    raw_size: 0x200,
                    raw_pointer: 0x200,
                    characteristics: 0,
                },
            ],
        };
        let image: Vec<u8> = vec![0; 0x400];
        assert_eq!(
            validate_section_map(&image, &pe),
            Err(ScanFailure::Metadata)
        );
    }

    #[test]
    fn table_preflight_rejects_member_ref_quota() {
        let stream: TableStream = TableStream {
            heap_sizes: 0,
            valid: 0,
            sorted: 0,
            row_counts: BTreeMap::from([(TableId::MemberRef.index(), MAX_MEMBER_REF_ROWS + 1)]),
        };
        assert_eq!(
            preflight_table_counts(&stream),
            Err(ScanFailure::TableLimit)
        );
    }

    #[test]
    fn incomplete_carrier_rejects_complete_recovery_transactionally() {
        let complete: CompleteCarrier = CompleteCarrier {
            accessor_count: 0,
            recovered: Vec::new(),
        };
        let recovery: ObfuscarStringRecovery =
            aggregate_carrier_scans([CarrierScan::Complete(complete), CarrierScan::Incomplete]);
        assert_eq!(recovery.carrier_count, 1);
        assert!(recovery.unknown_reason.is_some());
        assert!(recovery.recovered.is_empty());
    }

    #[test]
    fn ambiguous_carrier_count_is_exact() {
        let complete: CompleteCarrier = CompleteCarrier {
            accessor_count: 0,
            recovered: Vec::new(),
        };
        let recovery: ObfuscarStringRecovery = aggregate_carrier_scans([
            CarrierScan::Complete(complete.clone()),
            CarrierScan::Complete(complete.clone()),
            CarrierScan::Complete(complete),
        ]);
        assert_eq!(recovery.carrier_count, 3);
        assert!(recovery.unknown_reason.is_some());
    }
}
