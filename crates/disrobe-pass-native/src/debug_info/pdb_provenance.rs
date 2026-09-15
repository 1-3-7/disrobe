use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Cursor;

use disrobe_bytes::{ByteReadError, ByteReader};
use pdb::FallibleIterator as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DBI_STREAM: pdb::StreamIndex = pdb::StreamIndex(3);
const IPI_STREAM: pdb::StreamIndex = pdb::StreamIndex(4);
const LF_BUILDINFO: u16 = 0x1603;
const LF_SUBSTR_LIST: u16 = 0x1604;
const LF_STRING_ID: u16 = 0x1605;
const S_OBJNAME: u16 = 0x1101;
const S_COMPILE2: u16 = 0x1116;
const S_COMPILE3: u16 = 0x113c;
const S_ENVBLOCK: u16 = 0x113d;
const S_BUILDINFO: u16 = 0x114c;
const MAX_IPI_RECORDS: usize = 1_000_000;
const MAX_MODULES: usize = 65_536;
const MAX_MODULE_SYMBOLS: usize = 1_000_000;
const MAX_RESOLVED_STRING_BYTES: usize = 1024 * 1024;
const MAX_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SUBSTRING_REFERENCES: usize = 16_384;
const MAX_SUBSTRING_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbBuildProvenance {
    pub guid_hex: String,
    pub age: u32,
    pub dbi_version: PdbDbiVersion,
    pub modules: Vec<PdbModuleProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbModuleProvenance {
    pub module_index: u32,
    pub module_name: String,
    pub compilers: Vec<PdbCompilerRecord>,
    pub observations: Vec<PdbProvenanceObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbCompilerRecord {
    pub source: PdbProvenanceSource,
    pub record_offset: u32,
    pub language: String,
    pub machine: String,
    pub frontend_version: PdbVersion,
    pub backend_version: PdbVersion,
    pub version_string: PdbByteString,
    pub flags: PdbCompileFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbVersion {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub qfe: Option<u16>,
}

pub type PdbDbiVersion = PdbVersion;

impl fmt::Display for PdbVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}.{}.{}.{}",
            self.major,
            self.minor,
            self.build,
            self.qfe.unwrap_or(0)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbCompileFlags {
    pub security_checks: bool,
    pub hot_patch: bool,
    pub profile_guided_optimization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbProvenanceObservation {
    pub source: PdbProvenanceSource,
    pub field: PdbProvenanceField,
    pub record_offset: u32,
    pub key: Option<PdbByteString>,
    pub value: PdbByteString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PdbProvenanceSource {
    DbiHeader,
    LfBuildInfo,
    SObjName,
    SCompile2,
    SCompile3,
    SEnvBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PdbProvenanceField {
    WorkingDirectory,
    ToolPath,
    SourcePath,
    ProgramDatabasePath,
    Arguments,
    ObjectPath,
    Environment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdbByteString {
    pub bytes_hex: String,
    pub utf8: Option<String>,
}

impl PdbByteString {
    fn from_bytes(bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bytes_hex: String = String::with_capacity(bytes.len());
        for byte in bytes {
            bytes_hex.push(char::from(HEX[usize::from(*byte >> 4)]));
            bytes_hex.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
        let utf8: Option<String> = std::str::from_utf8(bytes).ok().map(ToOwned::to_owned);
        Self { bytes_hex, utf8 }
    }

    fn byte_len(&self) -> usize {
        self.bytes_hex.len() / 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PdbProvenanceError {
    #[error("PDB stream read failed: {0}")]
    Pdb(String),
    #[error(
        "{context} is truncated at offset {offset}: need {needed} byte(s), {available} available"
    )]
    Truncated {
        context: &'static str,
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("invalid IPI header: {reason}")]
    InvalidIpiHeader { reason: &'static str },
    #[error("IPI record count {actual} exceeds limit {limit}")]
    IpiRecordLimit { actual: usize, limit: usize },
    #[error("IPI record count mismatch: header declares {declared}, parsed {parsed}")]
    IpiRecordCountMismatch { declared: usize, parsed: usize },
    #[error("build-info record {index:#x} has {count} arguments instead of 5")]
    BuildInfoArgumentCount { index: u32, count: u16 },
    #[error("substring list {index:#x} has {actual} references, limit {limit}")]
    SubstringReferenceLimit {
        index: u32,
        actual: usize,
        limit: usize,
    },
    #[error("IPI index {index:#x} is outside [{minimum:#x}, {maximum:#x})")]
    IndexOutOfRange {
        index: u32,
        minimum: u32,
        maximum: u32,
    },
    #[error("IPI index {index:#x} has leaf {actual:#06x}, expected {expected:#06x}")]
    WrongLeafKind {
        index: u32,
        expected: u16,
        actual: u16,
    },
    #[error("substring graph contains a cycle at IPI index {index:#x}")]
    SubstringCycle { index: u32 },
    #[error("substring depth exceeds {limit} at IPI index {index:#x}")]
    SubstringDepth { index: u32, limit: usize },
    #[error("substring traversal exceeds {limit} references")]
    SubstringTraversalLimit { limit: usize },
    #[error("resolved string at IPI index {index:#x} is {actual} bytes, limit {limit}")]
    ResolvedStringLimit {
        index: u32,
        actual: usize,
        limit: usize,
    },
    #[error("checked arithmetic overflow while parsing {context}")]
    ArithmeticOverflow { context: &'static str },
    #[error("DBI header signature is {actual:#010x}, expected 0xffffffff")]
    InvalidDbiSignature { actual: u32 },
    #[error("module count exceeds {limit}")]
    ModuleLimit { limit: usize },
    #[error("module {module_index} symbol count exceeds {limit}")]
    ModuleSymbolLimit { module_index: u32, limit: usize },
    #[error("module {module_index} symbol {record_offset} kind {kind:#06x} is malformed: {detail}")]
    MalformedSymbol {
        module_index: u32,
        record_offset: u32,
        kind: u16,
        detail: String,
    },
    #[error("module {module_index} environment record {record_offset} is not fully terminated")]
    EnvironmentNotTerminated {
        module_index: u32,
        record_offset: u32,
    },
    #[error("module {module_index} environment record {record_offset} has trailing bytes")]
    EnvironmentTrailingBytes {
        module_index: u32,
        record_offset: u32,
    },
    #[error("aggregate provenance is {actual} bytes, limit {limit}")]
    AggregateLimit { actual: usize, limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IpiRecord {
    BuildInfo([u32; 5]),
    SubstringList(Vec<u32>),
    StringId {
        prefix_list: Option<u32>,
        bytes: Vec<u8>,
    },
    Other(u16),
}

impl IpiRecord {
    const fn kind(&self) -> u16 {
        match self {
            Self::BuildInfo(_) => LF_BUILDINFO,
            Self::SubstringList(_) => LF_SUBSTR_LIST,
            Self::StringId { .. } => LF_STRING_ID,
            Self::Other(kind) => *kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpiRecords {
    minimum_index: u32,
    maximum_index: u32,
    records: BTreeMap<u32, IpiRecord>,
}

impl IpiRecords {
    fn empty() -> Self {
        Self {
            minimum_index: 0x1000,
            maximum_index: 0x1000,
            records: BTreeMap::new(),
        }
    }

    fn record(&self, index: u32) -> Result<&IpiRecord, PdbProvenanceError> {
        if index < self.minimum_index || index >= self.maximum_index {
            return Err(PdbProvenanceError::IndexOutOfRange {
                index,
                minimum: self.minimum_index,
                maximum: self.maximum_index,
            });
        }
        self.records
            .get(&index)
            .ok_or(PdbProvenanceError::IndexOutOfRange {
                index,
                minimum: self.minimum_index,
                maximum: self.maximum_index,
            })
    }

    fn resolve_build_info(&self, index: u32) -> Result<[PdbByteString; 5], PdbProvenanceError> {
        let record: &IpiRecord = self.record(index)?;
        let IpiRecord::BuildInfo(arguments) = record else {
            return Err(PdbProvenanceError::WrongLeafKind {
                index,
                expected: LF_BUILDINFO,
                actual: record.kind(),
            });
        };
        let mut state: ResolveState = ResolveState::default();
        let mut resolved: [PdbByteString; 5] =
            std::array::from_fn(|_index: usize| PdbByteString::from_bytes(&[]));
        for (slot, argument) in resolved.iter_mut().zip(arguments.iter()) {
            let bytes: Vec<u8> = self.resolve_string_bytes(*argument, 0, &mut state)?;
            *slot = PdbByteString::from_bytes(&bytes);
        }
        Ok(resolved)
    }

    #[cfg(test)]
    fn resolve_string(&self, index: u32) -> Result<PdbByteString, PdbProvenanceError> {
        let mut state: ResolveState = ResolveState::default();
        let bytes: Vec<u8> = self.resolve_string_bytes(index, 0, &mut state)?;
        Ok(PdbByteString::from_bytes(&bytes))
    }

    fn resolve_string_bytes(
        &self,
        index: u32,
        depth: usize,
        state: &mut ResolveState,
    ) -> Result<Vec<u8>, PdbProvenanceError> {
        state.visit(index, depth)?;
        let record: &IpiRecord = self.record(index)?;
        let IpiRecord::StringId { prefix_list, bytes } = record else {
            return Err(PdbProvenanceError::WrongLeafKind {
                index,
                expected: LF_STRING_ID,
                actual: record.kind(),
            });
        };
        let mut resolved: Vec<u8> = if let Some(prefix_index) = prefix_list {
            self.resolve_substring_list(*prefix_index, depth + 1, state)?
        } else {
            Vec::new()
        };
        append_resolved(&mut resolved, bytes, index)?;
        state.visiting.remove(&index);
        Ok(resolved)
    }

    fn resolve_substring_list(
        &self,
        index: u32,
        depth: usize,
        state: &mut ResolveState,
    ) -> Result<Vec<u8>, PdbProvenanceError> {
        state.visit(index, depth)?;
        let record: &IpiRecord = self.record(index)?;
        let IpiRecord::SubstringList(substrings) = record else {
            return Err(PdbProvenanceError::WrongLeafKind {
                index,
                expected: LF_SUBSTR_LIST,
                actual: record.kind(),
            });
        };
        let mut resolved: Vec<u8> = Vec::new();
        for substring in substrings {
            let bytes: Vec<u8> = self.resolve_string_bytes(*substring, depth + 1, state)?;
            append_resolved(&mut resolved, &bytes, index)?;
        }
        state.visiting.remove(&index);
        Ok(resolved)
    }
}

#[derive(Debug, Default)]
struct ResolveState {
    visiting: BTreeSet<u32>,
    references: usize,
}

impl ResolveState {
    fn visit(&mut self, index: u32, depth: usize) -> Result<(), PdbProvenanceError> {
        if depth > MAX_SUBSTRING_DEPTH {
            return Err(PdbProvenanceError::SubstringDepth {
                index,
                limit: MAX_SUBSTRING_DEPTH,
            });
        }
        self.references =
            self.references
                .checked_add(1)
                .ok_or(PdbProvenanceError::ArithmeticOverflow {
                    context: "substring reference count",
                })?;
        if self.references > MAX_SUBSTRING_REFERENCES {
            return Err(PdbProvenanceError::SubstringTraversalLimit {
                limit: MAX_SUBSTRING_REFERENCES,
            });
        }
        if !self.visiting.insert(index) {
            return Err(PdbProvenanceError::SubstringCycle { index });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedEnvironment {
    entries: Vec<(PdbByteString, PdbByteString)>,
}

pub(super) fn recover_pdb_build_provenance<'s>(
    pdb: &mut pdb::PDB<'s, Cursor<&'s [u8]>>,
    guid_hex: String,
    age: u32,
) -> Result<PdbBuildProvenance, PdbProvenanceError> {
    let ipi_records: IpiRecords = match pdb.raw_stream(IPI_STREAM) {
        Ok(Some(stream)) => parse_ipi_records(stream.as_slice())?,
        Ok(None) | Err(pdb::Error::StreamNotFound(4)) => IpiRecords::empty(),
        Err(error) => return Err(PdbProvenanceError::Pdb(error.to_string())),
    };
    let dbi_version: PdbDbiVersion = match pdb
        .raw_stream(DBI_STREAM)
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?
    {
        Some(stream) => parse_dbi_version(stream.as_slice())?,
        None => return Err(PdbProvenanceError::Pdb("DBI stream is absent".to_owned())),
    };
    let debug_information: pdb::DebugInformation<'_> = pdb
        .debug_information()
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?;
    let mut modules: pdb::ModuleIter<'_> = debug_information
        .modules()
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?;
    let mut reports: Vec<PdbModuleProvenance> = Vec::new();
    let mut aggregate_bytes: usize = 0;
    while let Some(module) = modules
        .next()
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?
    {
        if reports.len() >= MAX_MODULES {
            return Err(PdbProvenanceError::ModuleLimit { limit: MAX_MODULES });
        }
        let module_index: u32 = u32::try_from(reports.len()).map_err(|_error| {
            PdbProvenanceError::ArithmeticOverflow {
                context: "module index",
            }
        })?;
        let module_name: String = module.module_name().into_owned();
        account_bytes(&mut aggregate_bytes, module_name.len())?;
        let mut report: PdbModuleProvenance = PdbModuleProvenance {
            module_index,
            module_name,
            compilers: Vec::new(),
            observations: Vec::new(),
        };
        if let Some(module_info) = pdb
            .module_info(&module)
            .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?
        {
            recover_module(
                &module_info,
                &ipi_records,
                &mut report,
                &mut aggregate_bytes,
            )?;
        }
        reports.push(report);
    }
    Ok(PdbBuildProvenance {
        guid_hex,
        age,
        dbi_version,
        modules: reports,
    })
}

fn recover_module(
    module_info: &pdb::ModuleInfo<'_>,
    ipi_records: &IpiRecords,
    report: &mut PdbModuleProvenance,
    aggregate_bytes: &mut usize,
) -> Result<(), PdbProvenanceError> {
    let mut symbols: pdb::SymbolIter<'_> = module_info
        .symbols()
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?;
    let mut symbol_count: usize = 0;
    while let Some(symbol) = symbols
        .next()
        .map_err(|error: pdb::Error| PdbProvenanceError::Pdb(error.to_string()))?
    {
        symbol_count =
            symbol_count
                .checked_add(1)
                .ok_or(PdbProvenanceError::ArithmeticOverflow {
                    context: "module symbol count",
                })?;
        if symbol_count > MAX_MODULE_SYMBOLS {
            return Err(PdbProvenanceError::ModuleSymbolLimit {
                module_index: report.module_index,
                limit: MAX_MODULE_SYMBOLS,
            });
        }
        let kind: u16 = symbol.raw_kind();
        let record_offset: u32 = symbol.index().0;
        if kind == S_ENVBLOCK {
            let environment: ParsedEnvironment = parse_environment_block(
                symbol.raw_bytes(),
                report.module_index,
                record_offset,
                *aggregate_bytes,
            )?;
            for (key, value) in environment.entries {
                let field: PdbProvenanceField = environment_field(&key);
                push_observation(
                    report,
                    PdbProvenanceObservation {
                        source: PdbProvenanceSource::SEnvBlock,
                        field,
                        record_offset,
                        key: Some(key),
                        value,
                    },
                    aggregate_bytes,
                )?;
            }
            continue;
        }
        let parsed: std::result::Result<pdb::SymbolData<'_>, pdb::Error> = symbol.parse();
        match parsed {
            Ok(pdb::SymbolData::ObjName(object)) => {
                let observation: PdbProvenanceObservation = PdbProvenanceObservation {
                    source: PdbProvenanceSource::SObjName,
                    field: PdbProvenanceField::ObjectPath,
                    record_offset,
                    key: None,
                    value: bounded_byte_string(object.name.as_bytes(), *aggregate_bytes)?,
                };
                push_observation(report, observation, aggregate_bytes)?;
            }
            Ok(pdb::SymbolData::CompileFlags(compiler)) => {
                let source: PdbProvenanceSource = if kind == S_COMPILE3 {
                    PdbProvenanceSource::SCompile3
                } else {
                    PdbProvenanceSource::SCompile2
                };
                let version_string: PdbByteString =
                    bounded_byte_string(compiler.version_string.as_bytes(), *aggregate_bytes)?;
                account_bytes(aggregate_bytes, version_string.byte_len())?;
                report.compilers.push(PdbCompilerRecord {
                    source,
                    record_offset,
                    language: format!("{:?}", compiler.language),
                    machine: format!("{:?}", compiler.cpu_type),
                    frontend_version: compiler_version(compiler.frontend_version),
                    backend_version: compiler_version(compiler.backend_version),
                    version_string,
                    flags: PdbCompileFlags {
                        security_checks: compiler.flags.security_checks,
                        hot_patch: compiler.flags.hot_patch,
                        profile_guided_optimization: compiler.flags.pgo,
                    },
                });
            }
            Ok(pdb::SymbolData::BuildInfo(build_info)) => {
                let values: [PdbByteString; 5] = ipi_records.resolve_build_info(build_info.id.0)?;
                let fields: [PdbProvenanceField; 5] = [
                    PdbProvenanceField::WorkingDirectory,
                    PdbProvenanceField::ToolPath,
                    PdbProvenanceField::SourcePath,
                    PdbProvenanceField::ProgramDatabasePath,
                    PdbProvenanceField::Arguments,
                ];
                for (field, value) in fields.into_iter().zip(values) {
                    push_observation(
                        report,
                        PdbProvenanceObservation {
                            source: PdbProvenanceSource::LfBuildInfo,
                            field,
                            record_offset,
                            key: None,
                            value,
                        },
                        aggregate_bytes,
                    )?;
                }
            }
            Ok(_) => {}
            Err(error) if is_provenance_symbol(kind) => {
                return Err(PdbProvenanceError::MalformedSymbol {
                    module_index: report.module_index,
                    record_offset,
                    kind,
                    detail: error.to_string(),
                });
            }
            Err(_) => {}
        }
    }
    Ok(())
}

const fn is_provenance_symbol(kind: u16) -> bool {
    matches!(
        kind,
        S_OBJNAME | S_COMPILE2 | S_COMPILE3 | S_ENVBLOCK | S_BUILDINFO
    )
}

fn compiler_version(version: pdb::CompilerVersion) -> PdbVersion {
    PdbVersion {
        major: version.major,
        minor: version.minor,
        build: version.build,
        qfe: version.qfe,
    }
}

fn environment_field(key: &PdbByteString) -> PdbProvenanceField {
    match key.utf8.as_deref() {
        Some("cwd") => PdbProvenanceField::WorkingDirectory,
        Some("exe") => PdbProvenanceField::ToolPath,
        Some("src") => PdbProvenanceField::SourcePath,
        Some("pdb") => PdbProvenanceField::ProgramDatabasePath,
        Some("cmd") => PdbProvenanceField::Arguments,
        _ => PdbProvenanceField::Environment,
    }
}

fn push_observation(
    report: &mut PdbModuleProvenance,
    observation: PdbProvenanceObservation,
    aggregate_bytes: &mut usize,
) -> Result<(), PdbProvenanceError> {
    account_bytes(aggregate_bytes, observation.value.byte_len())?;
    if let Some(key) = observation.key.as_ref() {
        account_bytes(aggregate_bytes, key.byte_len())?;
    }
    report.observations.push(observation);
    Ok(())
}

fn bounded_byte_string(
    bytes: &[u8],
    aggregate_start: usize,
) -> Result<PdbByteString, PdbProvenanceError> {
    let mut projected_aggregate: usize = aggregate_start;
    account_bytes(&mut projected_aggregate, bytes.len())?;
    Ok(PdbByteString::from_bytes(bytes))
}

fn account_bytes(total: &mut usize, addition: usize) -> Result<(), PdbProvenanceError> {
    let actual: usize =
        total
            .checked_add(addition)
            .ok_or(PdbProvenanceError::ArithmeticOverflow {
                context: "aggregate provenance bytes",
            })?;
    if actual > MAX_AGGREGATE_BYTES {
        return Err(PdbProvenanceError::AggregateLimit {
            actual,
            limit: MAX_AGGREGATE_BYTES,
        });
    }
    *total = actual;
    Ok(())
}

fn parse_dbi_version(bytes: &[u8]) -> Result<PdbDbiVersion, PdbProvenanceError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let signature: u32 = read_u32(&mut reader, "DBI header")?;
    if signature != u32::MAX {
        return Err(PdbProvenanceError::InvalidDbiSignature { actual: signature });
    }
    let _version: u32 = read_u32(&mut reader, "DBI header")?;
    let _age: u32 = read_u32(&mut reader, "DBI header")?;
    skip(&mut reader, 2, "DBI header")?;
    let internal_version: u16 = read_u16(&mut reader, "DBI header")?;
    skip(&mut reader, 2, "DBI header")?;
    let build: u16 = read_u16(&mut reader, "DBI header")?;
    skip(&mut reader, 2, "DBI header")?;
    let rebuild: u16 = read_u16(&mut reader, "DBI header")?;
    let (major, minor, qfe): (u16, u16, u16) = if internal_version & 0x8000 != 0 {
        (
            (internal_version >> 8) & 0x7f,
            internal_version & 0xff,
            rebuild,
        )
    } else {
        (
            (internal_version >> 11) & 0x1f,
            (internal_version >> 4) & 0x7f,
            internal_version & 0x0f,
        )
    };
    Ok(PdbVersion {
        major,
        minor,
        build,
        qfe: Some(qfe),
    })
}

fn parse_ipi_records(bytes: &[u8]) -> Result<IpiRecords, PdbProvenanceError> {
    if bytes.is_empty() {
        return Err(PdbProvenanceError::InvalidIpiHeader {
            reason: "present IPI stream is empty",
        });
    }
    let mut header: ByteReader<'_> = ByteReader::new(bytes);
    let _version: u32 = read_u32(&mut header, "IPI header")?;
    let header_size_u32: u32 = read_u32(&mut header, "IPI header")?;
    let minimum_index: u32 = read_u32(&mut header, "IPI header")?;
    let maximum_index: u32 = read_u32(&mut header, "IPI header")?;
    let record_bytes_u32: u32 = read_u32(&mut header, "IPI header")?;
    let header_size: usize = usize::try_from(header_size_u32).map_err(|_error| {
        PdbProvenanceError::ArithmeticOverflow {
            context: "IPI header size",
        }
    })?;
    if !(56..=1024).contains(&header_size) {
        return Err(PdbProvenanceError::InvalidIpiHeader {
            reason: "header size is outside 56..=1024",
        });
    }
    if minimum_index < 0x1000 {
        return Err(PdbProvenanceError::InvalidIpiHeader {
            reason: "minimum index is below 0x1000",
        });
    }
    let count_u32: u32 =
        maximum_index
            .checked_sub(minimum_index)
            .ok_or(PdbProvenanceError::InvalidIpiHeader {
                reason: "maximum index is below minimum index",
            })?;
    let count: usize =
        usize::try_from(count_u32).map_err(|_error| PdbProvenanceError::ArithmeticOverflow {
            context: "IPI record count",
        })?;
    if count > MAX_IPI_RECORDS {
        return Err(PdbProvenanceError::IpiRecordLimit {
            actual: count,
            limit: MAX_IPI_RECORDS,
        });
    }
    let record_bytes: usize = usize::try_from(record_bytes_u32).map_err(|_error| {
        PdbProvenanceError::ArithmeticOverflow {
            context: "IPI record bytes",
        }
    })?;
    let body_end: usize =
        header_size
            .checked_add(record_bytes)
            .ok_or(PdbProvenanceError::ArithmeticOverflow {
                context: "IPI record range",
            })?;
    let body: &[u8] = bytes.get(header_size..body_end).ok_or_else(|| {
        let available: usize = bytes.get(header_size..).map_or(0, <[u8]>::len);
        PdbProvenanceError::Truncated {
            context: "IPI records",
            offset: header_size,
            needed: record_bytes,
            available,
        }
    })?;
    let mut reader: ByteReader<'_> = ByteReader::new(body);
    let mut records: BTreeMap<u32, IpiRecord> = BTreeMap::new();
    for ordinal in 0..count {
        let length: usize = usize::from(read_u16(&mut reader, "IPI record length")?);
        if length < 2 {
            return Err(PdbProvenanceError::InvalidIpiHeader {
                reason: "IPI record length is smaller than its leaf",
            });
        }
        let record_bytes: &[u8] = reader
            .read_bytes(length)
            .map_err(|error: ByteReadError| truncated("IPI record", error))?;
        let ordinal_u32: u32 =
            u32::try_from(ordinal).map_err(|_error| PdbProvenanceError::ArithmeticOverflow {
                context: "IPI record ordinal",
            })?;
        let index: u32 = minimum_index.checked_add(ordinal_u32).ok_or(
            PdbProvenanceError::ArithmeticOverflow {
                context: "IPI record index",
            },
        )?;
        let record: IpiRecord = parse_ipi_record(index, record_bytes)?;
        records.insert(index, record);
    }
    if !reader.is_empty() {
        return Err(PdbProvenanceError::IpiRecordCountMismatch {
            declared: count,
            parsed: records.len(),
        });
    }
    Ok(IpiRecords {
        minimum_index,
        maximum_index,
        records,
    })
}

fn parse_ipi_record(index: u32, bytes: &[u8]) -> Result<IpiRecord, PdbProvenanceError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let kind: u16 = read_u16(&mut reader, "IPI record leaf")?;
    match kind {
        LF_BUILDINFO => {
            let count: u16 = read_u16(&mut reader, "LF_BUILDINFO count")?;
            if count != 5 {
                return Err(PdbProvenanceError::BuildInfoArgumentCount { index, count });
            }
            let mut arguments: [u32; 5] = [0u32; 5];
            for argument in &mut arguments {
                *argument = read_u32(&mut reader, "LF_BUILDINFO argument")?;
            }
            Ok(IpiRecord::BuildInfo(arguments))
        }
        LF_SUBSTR_LIST => {
            let count_u32: u32 = read_u32(&mut reader, "LF_SUBSTR_LIST count")?;
            let count: usize = usize::try_from(count_u32).map_err(|_error| {
                PdbProvenanceError::ArithmeticOverflow {
                    context: "LF_SUBSTR_LIST count",
                }
            })?;
            if count > MAX_SUBSTRING_REFERENCES {
                return Err(PdbProvenanceError::SubstringReferenceLimit {
                    index,
                    actual: count,
                    limit: MAX_SUBSTRING_REFERENCES,
                });
            }
            let required: usize =
                count
                    .checked_mul(4)
                    .ok_or(PdbProvenanceError::ArithmeticOverflow {
                        context: "LF_SUBSTR_LIST bytes",
                    })?;
            if required > reader.remaining() {
                return Err(PdbProvenanceError::Truncated {
                    context: "LF_SUBSTR_LIST references",
                    offset: reader.position(),
                    needed: required,
                    available: reader.remaining(),
                });
            }
            let mut substrings: Vec<u32> = Vec::with_capacity(count);
            for _ordinal in 0..count {
                substrings.push(read_u32(&mut reader, "LF_SUBSTR_LIST reference")?);
            }
            Ok(IpiRecord::SubstringList(substrings))
        }
        LF_STRING_ID => {
            let prefix: u32 = read_u32(&mut reader, "LF_STRING_ID prefix")?;
            let string_bytes: &[u8] = read_cstring_slice(&mut reader, "LF_STRING_ID string")?;
            if string_bytes.len() > MAX_RESOLVED_STRING_BYTES {
                return Err(PdbProvenanceError::ResolvedStringLimit {
                    index,
                    actual: string_bytes.len(),
                    limit: MAX_RESOLVED_STRING_BYTES,
                });
            }
            Ok(IpiRecord::StringId {
                prefix_list: (prefix != 0).then_some(prefix),
                bytes: string_bytes.to_vec(),
            })
        }
        _ => Ok(IpiRecord::Other(kind)),
    }
}

fn parse_environment_block(
    bytes: &[u8],
    module_index: u32,
    record_offset: u32,
    aggregate_start: usize,
) -> Result<ParsedEnvironment, PdbProvenanceError> {
    let mut reader: ByteReader<'_> = ByteReader::new(bytes);
    let kind: u16 = read_u16(&mut reader, "S_ENVBLOCK kind")?;
    if kind != S_ENVBLOCK {
        return Err(PdbProvenanceError::WrongLeafKind {
            index: record_offset,
            expected: S_ENVBLOCK,
            actual: kind,
        });
    }
    let _flags: u8 = reader
        .read_u8()
        .map_err(|error: ByteReadError| truncated("S_ENVBLOCK flags", error))?;
    let mut entries: Vec<(PdbByteString, PdbByteString)> = Vec::new();
    let mut projected_aggregate: usize = aggregate_start;
    loop {
        if reader.is_empty() {
            return Err(PdbProvenanceError::EnvironmentNotTerminated {
                module_index,
                record_offset,
            });
        }
        let key_bytes: &[u8] = read_environment_string(&mut reader, module_index, record_offset)?;
        if key_bytes.is_empty() {
            break;
        }
        if reader.is_empty() {
            return Err(PdbProvenanceError::EnvironmentNotTerminated {
                module_index,
                record_offset,
            });
        }
        let value_bytes: &[u8] = read_environment_string(&mut reader, module_index, record_offset)?;
        account_bytes(&mut projected_aggregate, key_bytes.len())?;
        account_bytes(&mut projected_aggregate, value_bytes.len())?;
        entries.push((
            PdbByteString::from_bytes(key_bytes),
            PdbByteString::from_bytes(value_bytes),
        ));
    }
    if !reader.is_empty() {
        return Err(PdbProvenanceError::EnvironmentTrailingBytes {
            module_index,
            record_offset,
        });
    }
    Ok(ParsedEnvironment { entries })
}

fn read_environment_string<'a>(
    reader: &mut ByteReader<'a>,
    module_index: u32,
    record_offset: u32,
) -> Result<&'a [u8], PdbProvenanceError> {
    read_cstring_slice(reader, "S_ENVBLOCK string").map_err(|error: PdbProvenanceError| match error
    {
        PdbProvenanceError::Truncated { .. } => PdbProvenanceError::EnvironmentNotTerminated {
            module_index,
            record_offset,
        },
        other => other,
    })
}

fn read_cstring_slice<'a>(
    reader: &mut ByteReader<'a>,
    context: &'static str,
) -> Result<&'a [u8], PdbProvenanceError> {
    let position: usize = reader.position();
    let remaining: &[u8] =
        reader
            .as_slice()
            .get(position..)
            .ok_or(PdbProvenanceError::ArithmeticOverflow {
                context: "C string range",
            })?;
    let needed: usize =
        remaining
            .len()
            .checked_add(1)
            .ok_or(PdbProvenanceError::ArithmeticOverflow {
                context: "C string terminator length",
            })?;
    let length: usize =
        remaining
            .iter()
            .position(|byte: &u8| *byte == 0)
            .ok_or(PdbProvenanceError::Truncated {
                context,
                offset: position,
                needed,
                available: remaining.len(),
            })?;
    let bytes: &[u8] = reader
        .read_bytes(length)
        .map_err(|error: ByteReadError| truncated(context, error))?;
    reader
        .skip(1)
        .map_err(|error: ByteReadError| truncated(context, error))?;
    Ok(bytes)
}

fn append_resolved(
    destination: &mut Vec<u8>,
    source: &[u8],
    index: u32,
) -> Result<(), PdbProvenanceError> {
    let actual: usize = destination.len().checked_add(source.len()).ok_or(
        PdbProvenanceError::ArithmeticOverflow {
            context: "resolved string length",
        },
    )?;
    if actual > MAX_RESOLVED_STRING_BYTES {
        return Err(PdbProvenanceError::ResolvedStringLimit {
            index,
            actual,
            limit: MAX_RESOLVED_STRING_BYTES,
        });
    }
    destination.extend_from_slice(source);
    Ok(())
}

fn read_u16(reader: &mut ByteReader<'_>, context: &'static str) -> Result<u16, PdbProvenanceError> {
    reader
        .read_u16_le()
        .map_err(|error: ByteReadError| truncated(context, error))
}

fn read_u32(reader: &mut ByteReader<'_>, context: &'static str) -> Result<u32, PdbProvenanceError> {
    reader
        .read_u32_le()
        .map_err(|error: ByteReadError| truncated(context, error))
}

fn skip(
    reader: &mut ByteReader<'_>,
    count: usize,
    context: &'static str,
) -> Result<(), PdbProvenanceError> {
    reader
        .skip(count)
        .map_err(|error: ByteReadError| truncated(context, error))
}

const fn truncated(context: &'static str, error: ByteReadError) -> PdbProvenanceError {
    PdbProvenanceError::Truncated {
        context,
        offset: error.offset,
        needed: error.needed,
        available: error.available,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const LF_BUILDINFO: u16 = 0x1603;
    const LF_SUBSTR_LIST: u16 = 0x1604;
    const LF_STRING_ID: u16 = 0x1605;
    const S_ENVBLOCK: u16 = 0x113d;

    fn ipi_record(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length: u16 = u16::try_from(2usize + payload.len()).expect("bounded test record");
        let mut record: Vec<u8> = Vec::new();
        record.extend_from_slice(&length.to_le_bytes());
        record.extend_from_slice(&kind.to_le_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn ipi_stream(records: &[Vec<u8>]) -> Vec<u8> {
        let record_bytes: usize = records.iter().map(Vec::len).sum();
        let maximum_index: u32 = 0x1000u32
            .checked_add(u32::try_from(records.len()).expect("bounded record count"))
            .expect("bounded maximum index");
        let mut stream: Vec<u8> = Vec::new();
        stream.extend_from_slice(&20_040_203u32.to_le_bytes());
        stream.extend_from_slice(&56u32.to_le_bytes());
        stream.extend_from_slice(&0x1000u32.to_le_bytes());
        stream.extend_from_slice(&maximum_index.to_le_bytes());
        stream.extend_from_slice(
            &u32::try_from(record_bytes)
                .expect("bounded record bytes")
                .to_le_bytes(),
        );
        stream.extend_from_slice(&u16::MAX.to_le_bytes());
        stream.extend_from_slice(&u16::MAX.to_le_bytes());
        stream.extend_from_slice(&4u32.to_le_bytes());
        stream.extend_from_slice(&0x3ffffu32.to_le_bytes());
        stream.extend_from_slice(&0i32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0i32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        stream.extend_from_slice(&0i32.to_le_bytes());
        stream.extend_from_slice(&0u32.to_le_bytes());
        for record in records {
            stream.extend_from_slice(record);
        }
        stream
    }

    fn string_id(prefix: u32, bytes: &[u8]) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&prefix.to_le_bytes());
        payload.extend_from_slice(bytes);
        payload.push(0);
        ipi_record(LF_STRING_ID, &payload)
    }

    #[test]
    fn ipi_parser_rejects_truncated_record() {
        let mut stream: Vec<u8> = ipi_stream(&[ipi_record(LF_STRING_ID, &[0, 0, 0, 0, 0])]);
        stream.pop();
        let error: PdbProvenanceError =
            parse_ipi_records(&stream).expect_err("truncated record must fail");
        assert!(matches!(error, PdbProvenanceError::Truncated { .. }));
    }

    #[test]
    fn ipi_parser_distinguishes_empty_present_stream_from_absence() {
        let error: PdbProvenanceError =
            parse_ipi_records(&[]).expect_err("present empty IPI stream must be malformed");
        assert_eq!(
            error,
            PdbProvenanceError::InvalidIpiHeader {
                reason: "present IPI stream is empty",
            }
        );
    }

    #[test]
    fn ipi_parser_rejects_oversized_build_info_argument_count() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&6u16.to_le_bytes());
        for index in 0x1000u32..0x1006u32 {
            payload.extend_from_slice(&index.to_le_bytes());
        }
        let stream: Vec<u8> = ipi_stream(&[ipi_record(LF_BUILDINFO, &payload)]);
        let error: PdbProvenanceError =
            parse_ipi_records(&stream).expect_err("six build-info arguments must fail");
        assert_eq!(
            error,
            PdbProvenanceError::BuildInfoArgumentCount {
                index: 0x1000,
                count: 6,
            }
        );
    }

    #[test]
    fn build_info_rejects_out_of_range_string_index() {
        let mut build_payload: Vec<u8> = Vec::new();
        build_payload.extend_from_slice(&5u16.to_le_bytes());
        for _ in 0..5 {
            build_payload.extend_from_slice(&0x2000u32.to_le_bytes());
        }
        let stream: Vec<u8> = ipi_stream(&[ipi_record(LF_BUILDINFO, &build_payload)]);
        let records: IpiRecords = parse_ipi_records(&stream).expect("valid record framing");
        let error: PdbProvenanceError = records
            .resolve_build_info(0x1000)
            .expect_err("out-of-range string id must fail");
        assert!(matches!(
            error,
            PdbProvenanceError::IndexOutOfRange { index: 0x2000, .. }
        ));
    }

    #[test]
    fn substring_cycle_is_rejected() {
        let string: Vec<u8> = string_id(0x1001, b"");
        let mut list_payload: Vec<u8> = Vec::new();
        list_payload.extend_from_slice(&1u32.to_le_bytes());
        list_payload.extend_from_slice(&0x1000u32.to_le_bytes());
        let list: Vec<u8> = ipi_record(LF_SUBSTR_LIST, &list_payload);
        let stream: Vec<u8> = ipi_stream(&[string, list]);
        let records: IpiRecords = parse_ipi_records(&stream).expect("valid cyclic framing");
        let error: PdbProvenanceError = records
            .resolve_string(0x1000)
            .expect_err("substring cycle must fail");
        assert!(matches!(
            error,
            PdbProvenanceError::SubstringCycle { index: 0x1000 }
        ));
    }

    #[test]
    fn substring_order_and_non_utf8_bytes_are_preserved() {
        let prefix: Vec<u8> = string_id(0, &[0xff, b'a']);
        let mut list_payload: Vec<u8> = Vec::new();
        list_payload.extend_from_slice(&1u32.to_le_bytes());
        list_payload.extend_from_slice(&0x1000u32.to_le_bytes());
        let list: Vec<u8> = ipi_record(LF_SUBSTR_LIST, &list_payload);
        let suffix: Vec<u8> = string_id(0x1001, b"bc");
        let stream: Vec<u8> = ipi_stream(&[prefix, list, suffix]);
        let records: IpiRecords = parse_ipi_records(&stream).expect("valid substring records");
        let value: PdbByteString = records
            .resolve_string(0x1002)
            .expect("resolve lossless string");
        assert_eq!(value.bytes_hex, "ff616263");
        assert_eq!(value.utf8, None);
    }

    #[test]
    fn environment_block_requires_final_terminator() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&S_ENVBLOCK.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(b"cwd\0value\0");
        let error: PdbProvenanceError = parse_environment_block(&raw, 0, 72, 0)
            .expect_err("environment block without final empty string must fail");
        assert!(matches!(
            error,
            PdbProvenanceError::EnvironmentNotTerminated {
                module_index: 0,
                record_offset: 72
            }
        ));
    }

    #[test]
    fn empty_environment_value_is_present_and_distinct() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&S_ENVBLOCK.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(b"cwd\0\0\0");
        let parsed: ParsedEnvironment =
            parse_environment_block(&raw, 0, 72, 0).expect("complete environment block");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].1.bytes_hex, "");
        assert_eq!(parsed.entries[0].1.utf8.as_deref(), Some(""));
    }

    #[test]
    fn environment_block_checks_aggregate_budget_before_allocation() {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&S_ENVBLOCK.to_le_bytes());
        raw.push(0);
        raw.extend_from_slice(b"k\0v\0\0");
        let error: PdbProvenanceError = parse_environment_block(&raw, 0, 72, MAX_AGGREGATE_BYTES)
            .expect_err("exhausted budget must reject environment values");
        assert_eq!(
            error,
            PdbProvenanceError::AggregateLimit {
                actual: MAX_AGGREGATE_BYTES + 1,
                limit: MAX_AGGREGATE_BYTES,
            }
        );
    }
}
