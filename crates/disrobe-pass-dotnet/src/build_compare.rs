use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fmt::Write as _;
use std::rc::Rc;

use serde::{Serialize, Serializer};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use crate::cil::{
    ExceptionClause, ExceptionClauseKind, Instruction, MethodBody, OperandValue,
    method_body_extent, parse_method_body,
};
use crate::error::Error;
use crate::metadata::{
    MetadataRoot, StreamHeader, TableStream, decompress_uint, metadata_slice, parse_metadata_root,
    parse_table_stream,
};
use crate::pe::{ClrHeader, DataDirectory, PeImage, parse, parse_clr_header};
use crate::tables::{
    CodedIndex, HeapWidths, RowRef, TableId, TableSpan, Tables, TypeDefRow, indirection_for,
    parse_tables, table_spans,
};

pub const SCHEMA: &str = "disrobe.dotnet.build-compare/v1";

const MAX_NAME_BYTES: usize = 16 * 1024;
const MAX_RENDERED_BYTES: usize = 256 * 1024 * 1024;
const MAX_IL_BYTES: usize = 256 * 1024 * 1024;
const MAX_SIGNATURE_DEPTH: usize = 32;
const MAX_TYPE_NESTING: usize = 64;
const MAX_ARRAY_RANK: u32 = 64;
const MAX_DEBUG_ENTRIES: usize = 1024;
const DEBUG_DIRECTORY_INDEX: usize = 6;
const DEBUG_ENTRY_SIZE: usize = 28;
const DEBUG_TYPE_REPRODUCIBLE: u32 = 16;
const SEMANTICS_SETTER: u16 = 0x0001;
const SEMANTICS_GETTER: u16 = 0x0002;
const SEMANTICS_OTHER: u16 = 0x0004;
const SEMANTICS_ADD: u16 = 0x0008;
const SEMANTICS_REMOVE: u16 = 0x0010;
const SEMANTICS_FIRE: u16 = 0x0020;
const METHOD_CODE_TYPE_MASK: u16 = 0x0003;
const USER_STRING_TABLE: u32 = 0x70;
const TARGET_FRAMEWORK: (&str, &str) = ("System.Runtime.Versioning", "TargetFrameworkAttribute");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Side {
    Old,
    New,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Old => "old",
            Self::New => "new",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompareError {
    #[error("DR-DOTNET-0960: the {side} assembly is not a readable .NET image: {source}")]
    Image { side: Side, source: Error },
    #[error("DR-DOTNET-0961: the {side} assembly is malformed at {location}: {reason}")]
    Malformed {
        side: Side,
        location: String,
        reason: String,
    },
    #[error("DR-DOTNET-0962: the {side} assembly exceeds the {what} bound of {limit}")]
    Bound {
        side: Side,
        what: &'static str,
        limit: usize,
    },
}

#[derive(Debug)]
enum Fault {
    Image(Error),
    Malformed { location: String, reason: String },
    Bound { what: &'static str, limit: usize },
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        Self::Image(error)
    }
}

impl Fault {
    fn malformed(location: impl fmt::Display, reason: impl Into<String>) -> Self {
        Self::Malformed {
            location: location.to_string(),
            reason: reason.into(),
        }
    }

    fn on(self, side: Side) -> CompareError {
        match self {
            Self::Image(source) => CompareError::Image { side, source },
            Self::Malformed { location, reason } => CompareError::Malformed {
                side,
                location,
                reason,
            },
            Self::Bound { what, limit } => CompareError::Bound { side, what, limit },
        }
    }
}

type Outcome<T> = Result<T, Fault>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Location {
    Row { table: TableId, row: u32 },
    MetadataRoot,
    CoffHeader,
    CliHeader,
    DebugDirectory,
}

impl Location {
    const fn row(table: TableId, row: u32) -> Self {
        Self::Row { table, row }
    }
}

const fn table_name(table: TableId) -> &'static str {
    match table {
        TableId::Module => "Module",
        TableId::TypeRef => "TypeRef",
        TableId::TypeDef => "TypeDef",
        TableId::FieldPtr => "FieldPtr",
        TableId::Field => "Field",
        TableId::MethodPtr => "MethodPtr",
        TableId::MethodDef => "MethodDef",
        TableId::ParamPtr => "ParamPtr",
        TableId::Param => "Param",
        TableId::InterfaceImpl => "InterfaceImpl",
        TableId::MemberRef => "MemberRef",
        TableId::Constant => "Constant",
        TableId::CustomAttribute => "CustomAttribute",
        TableId::FieldMarshal => "FieldMarshal",
        TableId::DeclSecurity => "DeclSecurity",
        TableId::ClassLayout => "ClassLayout",
        TableId::FieldLayout => "FieldLayout",
        TableId::StandAloneSig => "StandAloneSig",
        TableId::EventMap => "EventMap",
        TableId::EventPtr => "EventPtr",
        TableId::Event => "Event",
        TableId::PropertyMap => "PropertyMap",
        TableId::PropertyPtr => "PropertyPtr",
        TableId::Property => "Property",
        TableId::MethodSemantics => "MethodSemantics",
        TableId::MethodImpl => "MethodImpl",
        TableId::ModuleRef => "ModuleRef",
        TableId::TypeSpec => "TypeSpec",
        TableId::ImplMap => "ImplMap",
        TableId::FieldRva => "FieldRva",
        TableId::Assembly => "Assembly",
        TableId::AssemblyProcessor => "AssemblyProcessor",
        TableId::AssemblyOs => "AssemblyOS",
        TableId::AssemblyRef => "AssemblyRef",
        TableId::AssemblyRefProcessor => "AssemblyRefProcessor",
        TableId::AssemblyRefOs => "AssemblyRefOS",
        TableId::File => "File",
        TableId::ExportedType => "ExportedType",
        TableId::ManifestResource => "ManifestResource",
        TableId::NestedClass => "NestedClass",
        TableId::GenericParam => "GenericParam",
        TableId::MethodSpec => "MethodSpec",
        TableId::GenericParamConstraint => "GenericParamConstraint",
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Row { table, row } => write!(f, "{}#{row}", table_name(*table)),
            Self::MetadataRoot => f.write_str("metadata-root"),
            Self::CoffHeader => f.write_str("coff-header"),
            Self::CliHeader => f.write_str("cli-header"),
            Self::DebugDirectory => f.write_str("debug-directory"),
        }
    }
}

impl Serialize for Location {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Entity {
    Identity,
    AssemblyRef,
    Type,
    Field,
    Method,
    Property,
    Event,
    Pinvoke,
    Resource,
    Attribute,
}

impl Entity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::AssemblyRef => "assembly-ref",
            Self::Type => "type",
            Self::Field => "field",
            Self::Method => "method",
            Self::Property => "property",
            Self::Event => "event",
            Self::Pinvoke => "pinvoke",
            Self::Resource => "resource",
            Self::Attribute => "attribute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Aspect {
    Signature,
    Version,
    Culture,
    Flags,
    PublicKey,
    Extends,
    Interfaces,
    GenericParameters,
    Layout,
    MethodImpls,
    Security,
    Type,
    Constant,
    Offset,
    Marshal,
    ImplFlags,
    Parameters,
    Accessors,
    Module,
    EntryPoint,
    Implementation,
    Size,
    Sha256,
    Value,
    #[serde(rename = "body il-changed")]
    BodyIlChanged,
    #[serde(rename = "body token-renumbered")]
    BodyTokenRenumbered,
}

impl Aspect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Version => "version",
            Self::Culture => "culture",
            Self::Flags => "flags",
            Self::PublicKey => "public-key",
            Self::Extends => "extends",
            Self::Interfaces => "interfaces",
            Self::GenericParameters => "generic-parameters",
            Self::Layout => "layout",
            Self::MethodImpls => "method-impls",
            Self::Security => "security",
            Self::Type => "type",
            Self::Constant => "constant",
            Self::Offset => "offset",
            Self::Marshal => "marshal",
            Self::ImplFlags => "impl-flags",
            Self::Parameters => "parameters",
            Self::Accessors => "accessors",
            Self::Module => "module",
            Self::EntryPoint => "entry-point",
            Self::Implementation => "implementation",
            Self::Size => "size",
            Self::Sha256 => "sha256",
            Self::Value => "value",
            Self::BodyIlChanged => "body il-changed",
            Self::BodyTokenRenumbered => "body token-renumbered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityField {
    Name,
    Version,
    Culture,
    Flags,
    HashAlgorithm,
    PublicKeyToken,
    Security,
    TargetFramework,
    Module,
    Mvid,
    MetadataVersion,
    PeTimestamp,
    Machine,
    ClrFlags,
    Reproducible,
}

impl IdentityField {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Version => "version",
            Self::Culture => "culture",
            Self::Flags => "flags",
            Self::HashAlgorithm => "hash-algorithm",
            Self::PublicKeyToken => "public-key-token",
            Self::Security => "security",
            Self::TargetFramework => "target-framework",
            Self::Module => "module",
            Self::Mvid => "mvid",
            Self::MetadataVersion => "metadata-version",
            Self::PeTimestamp => "pe-timestamp",
            Self::Machine => "machine",
            Self::ClrFlags => "clr-flags",
            Self::Reproducible => "reproducible",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub entity: Entity,
    pub change: Change,
    pub key: String,
    pub aspect: Option<Aspect>,
    pub old: Option<String>,
    pub new: Option<String>,
    pub old_location: Option<Location>,
    pub new_location: Option<Location>,
}

struct Place(Option<Location>);

impl fmt::Display for Place {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(location) => location.fmt(f),
            None => f.write_str("-"),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entity: &str = self.entity.as_str();
        match self.change {
            Change::Added => {
                write!(f, "added {entity} {}", self.key)?;
                if let Some(value) = &self.new {
                    write!(f, " = {value}")?;
                }
                write!(f, " [{}]", Place(self.new_location))
            }
            Change::Removed => {
                write!(f, "removed {entity} {}", self.key)?;
                if let Some(value) = &self.old {
                    write!(f, " = {value}")?;
                }
                write!(f, " [{}]", Place(self.old_location))
            }
            Change::Changed => {
                write!(f, "changed {entity} {}", self.key)?;
                if let Some(aspect) = self.aspect {
                    write!(f, " {}", aspect.as_str())?;
                }
                write!(
                    f,
                    ": {} -> {} [{} -> {}]",
                    self.old.as_deref().unwrap_or("none"),
                    self.new.as_deref().unwrap_or("none"),
                    Place(self.old_location),
                    Place(self.new_location)
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssemblySummary {
    pub name: Option<String>,
    pub version: Option<String>,
    pub mvid: Option<String>,
    pub types: usize,
    pub methods: usize,
    pub fields: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildComparison {
    pub schema: &'static str,
    pub old: AssemblySummary,
    pub new: AssemblySummary,
    pub counts: BTreeMap<Entity, ChangeCounts>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ChangeCounts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}

impl BuildComparison {
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.findings.iter().map(ToString::to_string).collect()
    }
}

pub fn compare(old: &[u8], new: &[u8]) -> Result<BuildComparison, CompareError> {
    let old_image: Image<'_> = Image::load(old).map_err(|fault: Fault| fault.on(Side::Old))?;
    let new_image: Image<'_> = Image::load(new).map_err(|fault: Fault| fault.on(Side::New))?;
    let mut old_namer: Namer<'_, '_> = Namer::new(&old_image);
    let mut new_namer: Namer<'_, '_> = Namer::new(&new_image);
    let old_facts: Facts =
        Facts::read(&mut old_namer).map_err(|fault: Fault| fault.on(Side::Old))?;
    let new_facts: Facts =
        Facts::read(&mut new_namer).map_err(|fault: Fault| fault.on(Side::New))?;
    let mut findings: Vec<Finding> = Vec::new();
    diff_identity(&old_facts.identity, &new_facts.identity, &mut findings);
    let mut bodies: Bodies<'_, '_, '_> = Bodies {
        old: &mut old_namer,
        new: &mut new_namer,
    };
    for (entity, olds) in &old_facts.entities {
        let news: &[Entry] = new_facts.entities.get(entity).map_or(&[], Vec::as_slice);
        diff_entries(*entity, olds, news, &mut bodies, &mut findings)?;
    }
    diff_attributes(&old_facts.attributes, &new_facts.attributes, &mut findings);
    let mut ordered: Vec<(String, Finding)> = findings
        .into_iter()
        .map(|finding: Finding| (finding.to_string(), finding))
        .collect();
    ordered.sort_by(|left: &(String, Finding), right: &(String, Finding)| left.0.cmp(&right.0));
    let findings: Vec<Finding> = ordered
        .into_iter()
        .map(|(_, finding): (String, Finding)| finding)
        .collect();
    let mut counts: BTreeMap<Entity, ChangeCounts> = BTreeMap::new();
    for finding in &findings {
        let slot: &mut ChangeCounts = counts.entry(finding.entity).or_default();
        match finding.change {
            Change::Added => slot.added += 1,
            Change::Removed => slot.removed += 1,
            Change::Changed => slot.changed += 1,
        }
    }
    Ok(BuildComparison {
        schema: SCHEMA,
        old: old_facts.summary,
        new: new_facts.summary,
        counts,
        findings,
    })
}

#[derive(Debug, Clone, Copy)]
struct PropertyRow {
    flags: u16,
    name: u32,
    signature: u32,
}

#[derive(Debug, Clone, Copy)]
struct EventRow {
    flags: u16,
    name: u32,
    event_type: Option<RowRef>,
}

#[derive(Debug, Clone, Copy)]
struct MapRow {
    parent: u32,
    list: u32,
}

#[derive(Debug, Clone, Copy)]
struct SemanticsRow {
    semantics: u16,
    method: u32,
    association: Option<RowRef>,
}

#[derive(Debug, Clone, Copy)]
struct ConstraintRow {
    owner: u32,
    constraint: Option<RowRef>,
}

#[derive(Debug, Clone, Copy)]
struct SecurityRow {
    action: u16,
    parent: Option<RowRef>,
    permission_set: u32,
}

#[derive(Debug, Clone, Copy)]
struct ExportedTypeRow {
    namespace: u32,
    name: u32,
}

#[derive(Debug, Default)]
struct Extra {
    properties: Vec<PropertyRow>,
    events: Vec<EventRow>,
    property_maps: Vec<MapRow>,
    event_maps: Vec<MapRow>,
    semantics: Vec<SemanticsRow>,
    constraints: Vec<ConstraintRow>,
    field_layouts: Vec<(u32, u32)>,
    field_marshals: Vec<(Option<RowRef>, u32)>,
    security: Vec<SecurityRow>,
    files: Vec<u32>,
    exported_types: Vec<ExportedTypeRow>,
}

#[derive(Debug)]
struct Widths<'t> {
    heap: HeapWidths,
    counts: &'t BTreeMap<u8, u32>,
}

impl Widths<'_> {
    fn rows(&self, table: TableId) -> u32 {
        self.counts.get(&table.index()).copied().unwrap_or(0)
    }

    fn simple(&self, table: TableId) -> usize {
        if self.rows(table) >= 0x1_0000 { 4 } else { 2 }
    }

    fn list(&self, base: TableId) -> usize {
        self.simple(
            indirection_for(base)
                .filter(|pointer: &TableId| self.rows(*pointer) > 0)
                .unwrap_or(base),
        )
    }
}

#[derive(Debug)]
struct RowCursor<'s> {
    bytes: &'s [u8],
    position: usize,
    location: Location,
}

impl RowCursor<'_> {
    fn take(&mut self, width: usize) -> Outcome<&[u8]> {
        let end: usize = self.position.saturating_add(width);
        let slice: &[u8] = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| Fault::malformed(self.location, "row is shorter than its columns"))?;
        self.position = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Outcome<u16> {
        match *self.take(2)? {
            [a, b] => Ok(u16::from_le_bytes([a, b])),
            _ => Err(Fault::malformed(
                self.location,
                "row is shorter than its columns",
            )),
        }
    }

    fn u32(&mut self) -> Outcome<u32> {
        match *self.take(4)? {
            [a, b, c, d] => Ok(u32::from_le_bytes([a, b, c, d])),
            _ => Err(Fault::malformed(
                self.location,
                "row is shorter than its columns",
            )),
        }
    }

    fn index(&mut self, width: usize) -> Outcome<u32> {
        if width == 4 {
            self.u32()
        } else {
            self.u16().map(u32::from)
        }
    }

    fn coded(&mut self, width: usize, kind: CodedIndex) -> Outcome<Option<RowRef>> {
        let raw: u32 = self.index(width)?;
        let (table, row): (TableId, u32) = kind
            .decode(raw)
            .ok_or_else(|| Fault::malformed(self.location, "coded index names no table"))?;
        Ok((row != 0).then_some(RowRef { table, row }))
    }
}

#[derive(Debug)]
struct TableReader<'s> {
    stream: &'s [u8],
    spans: BTreeMap<u8, TableSpan>,
}

impl<'s> TableReader<'s> {
    fn cursor(&self, table: TableId, span: TableSpan, row: u32) -> Outcome<RowCursor<'s>> {
        let index: usize = usize::try_from(row.saturating_sub(1))
            .map_err(|_| Fault::malformed(Location::row(table, row), "row index overflows"))?;
        let start: usize = index
            .checked_mul(span.row_width)
            .and_then(|delta: usize| span.offset.checked_add(delta))
            .ok_or_else(|| Fault::malformed(Location::row(table, row), "row offset overflows"))?;
        let end: usize = start
            .checked_add(span.row_width)
            .ok_or_else(|| Fault::malformed(Location::row(table, row), "row offset overflows"))?;
        let bytes: &'s [u8] = self.stream.get(start..end).ok_or_else(|| {
            Fault::malformed(Location::row(table, row), "row lies past the table stream")
        })?;
        Ok(RowCursor {
            bytes,
            position: 0,
            location: Location::row(table, row),
        })
    }

    fn each<T>(
        &self,
        table: TableId,
        mut decode: impl FnMut(&mut RowCursor<'s>, usize) -> Outcome<T>,
    ) -> Outcome<Vec<T>> {
        let Some(span): Option<TableSpan> = self.spans.get(&table.index()).copied() else {
            return Ok(Vec::new());
        };
        let mut out: Vec<T> = Vec::with_capacity(span.rows as usize);
        for row in 1..=span.rows {
            let mut cursor: RowCursor<'s> = self.cursor(table, span, row)?;
            out.push(decode(&mut cursor, span.row_width)?);
        }
        Ok(out)
    }
}

fn remaining_width(location: Location, row_width: usize, used: usize) -> Outcome<usize> {
    match row_width.checked_sub(used) {
        Some(width @ (2 | 4)) => Ok(width),
        _ => Err(Fault::malformed(
            location,
            "row width leaves no 2- or 4-byte coded index",
        )),
    }
}

impl Extra {
    fn read(reader: &TableReader<'_>, widths: &Widths<'_>) -> Outcome<Self> {
        let strings: usize = widths.heap.strings;
        let blobs: usize = widths.heap.blob;
        let properties: Vec<PropertyRow> = reader.each(TableId::Property, |row, _| {
            Ok(PropertyRow {
                flags: row.u16()?,
                name: row.index(strings)?,
                signature: row.index(blobs)?,
            })
        })?;
        let events: Vec<EventRow> = reader.each(TableId::Event, |row, width| {
            let flags: u16 = row.u16()?;
            let name: u32 = row.index(strings)?;
            let coded: usize = remaining_width(row.location, width, 2 + strings)?;
            Ok(EventRow {
                flags,
                name,
                event_type: row.coded(coded, CodedIndex::TypeDefOrRef)?,
            })
        })?;
        let type_def: usize = widths.simple(TableId::TypeDef);
        let property_maps: Vec<MapRow> = reader.each(TableId::PropertyMap, |row, _| {
            Ok(MapRow {
                parent: row.index(type_def)?,
                list: row.index(widths.list(TableId::Property))?,
            })
        })?;
        let event_maps: Vec<MapRow> = reader.each(TableId::EventMap, |row, _| {
            Ok(MapRow {
                parent: row.index(type_def)?,
                list: row.index(widths.list(TableId::Event))?,
            })
        })?;
        let method_def: usize = widths.simple(TableId::MethodDef);
        let semantics: Vec<SemanticsRow> =
            reader.each(TableId::MethodSemantics, |row, width| {
                let semantics: u16 = row.u16()?;
                let method: u32 = row.index(method_def)?;
                let coded: usize = remaining_width(row.location, width, 2 + method_def)?;
                Ok(SemanticsRow {
                    semantics,
                    method,
                    association: row.coded(coded, CodedIndex::HasSemantics)?,
                })
            })?;
        let generic_param: usize = widths.simple(TableId::GenericParam);
        let constraints: Vec<ConstraintRow> =
            reader.each(TableId::GenericParamConstraint, |row, width| {
                let owner: u32 = row.index(generic_param)?;
                let coded: usize = remaining_width(row.location, width, generic_param)?;
                Ok(ConstraintRow {
                    owner,
                    constraint: row.coded(coded, CodedIndex::TypeDefOrRef)?,
                })
            })?;
        let field: usize = widths.simple(TableId::Field);
        let field_layouts: Vec<(u32, u32)> = reader.each(TableId::FieldLayout, |row, _| {
            Ok((row.u32()?, row.index(field)?))
        })?;
        let field_marshals: Vec<(Option<RowRef>, u32)> =
            reader.each(TableId::FieldMarshal, |row, width| {
                let coded: usize = remaining_width(row.location, width, blobs)?;
                Ok((
                    row.coded(coded, CodedIndex::HasFieldMarshal)?,
                    row.index(blobs)?,
                ))
            })?;
        let security: Vec<SecurityRow> = reader.each(TableId::DeclSecurity, |row, width| {
            let action: u16 = row.u16()?;
            let coded: usize = remaining_width(row.location, width, 2 + blobs)?;
            Ok(SecurityRow {
                action,
                parent: row.coded(coded, CodedIndex::HasDeclSecurity)?,
                permission_set: row.index(blobs)?,
            })
        })?;
        let files: Vec<u32> = reader.each(TableId::File, |row, _| {
            let _flags: u32 = row.u32()?;
            row.index(strings)
        })?;
        let exported_types: Vec<ExportedTypeRow> =
            reader.each(TableId::ExportedType, |row, _| {
                let _flags: u32 = row.u32()?;
                let _type_def_id: u32 = row.u32()?;
                Ok(ExportedTypeRow {
                    name: row.index(strings)?,
                    namespace: row.index(strings)?,
                })
            })?;
        Ok(Self {
            properties,
            events,
            property_maps,
            event_maps,
            semantics,
            constraints,
            field_layouts,
            field_marshals,
            security,
            files,
            exported_types,
        })
    }
}

#[derive(Debug)]
struct Membership {
    type_fields: Vec<Vec<u32>>,
    type_methods: Vec<Vec<u32>>,
    method_params: Vec<Vec<u32>>,
    type_properties: BTreeMap<u32, Vec<u32>>,
    type_events: BTreeMap<u32, Vec<u32>>,
    field_owner: BTreeMap<u32, u32>,
    method_owner: BTreeMap<u32, u32>,
    param_owner: BTreeMap<u32, u32>,
}

fn ranges(
    starts: &[u32],
    tables: &Tables,
    base: TableId,
    owner_table: TableId,
) -> Outcome<Vec<Vec<u32>>> {
    let list_rows: u32 = tables.list_rows(base);
    let mut out: Vec<Vec<u32>> = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().enumerate() {
        let owner: Location =
            Location::row(owner_table, u32::try_from(index + 1).unwrap_or(u32::MAX));
        let end: u32 = starts
            .get(index + 1)
            .copied()
            .unwrap_or_else(|| list_rows.saturating_add(1));
        if *start == 0 || *start > end || end > list_rows.saturating_add(1) {
            return Err(Fault::malformed(
                owner,
                "member list is out of order or out of range",
            ));
        }
        let mut members: Vec<u32> = Vec::with_capacity((end - start) as usize);
        for position in *start..end {
            let rid: u32 = tables
                .resolve_list_rid(base, position)
                .ok_or_else(|| Fault::malformed(owner, "member list names a missing row"))?;
            members.push(rid);
        }
        out.push(members);
    }
    Ok(out)
}

fn owners(lists: &[Vec<u32>]) -> BTreeMap<u32, u32> {
    let mut map: BTreeMap<u32, u32> = BTreeMap::new();
    for (index, members) in lists.iter().enumerate() {
        let owner: u32 = u32::try_from(index + 1).unwrap_or(u32::MAX);
        for rid in members {
            map.insert(*rid, owner);
        }
    }
    map
}

fn map_lists(
    maps: &[MapRow],
    tables: &Tables,
    base: TableId,
    map_table: TableId,
) -> Outcome<BTreeMap<u32, Vec<u32>>> {
    let starts: Vec<u32> = maps.iter().map(|map: &MapRow| map.list).collect();
    let lists: Vec<Vec<u32>> = ranges(&starts, tables, base, map_table)?;
    let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (map, members) in maps.iter().zip(lists) {
        out.entry(map.parent).or_default().extend(members);
    }
    Ok(out)
}

impl Membership {
    fn read(tables: &Tables, extra: &Extra) -> Outcome<Self> {
        let field_starts: Vec<u32> = tables
            .type_defs
            .iter()
            .map(|row: &TypeDefRow| row.field_list)
            .collect();
        let method_starts: Vec<u32> = tables
            .type_defs
            .iter()
            .map(|row: &TypeDefRow| row.method_list)
            .collect();
        let param_starts: Vec<u32> = tables.methods.iter().map(|row| row.param_list).collect();
        let type_fields: Vec<Vec<u32>> =
            ranges(&field_starts, tables, TableId::Field, TableId::TypeDef)?;
        let type_methods: Vec<Vec<u32>> =
            ranges(&method_starts, tables, TableId::MethodDef, TableId::TypeDef)?;
        let method_params: Vec<Vec<u32>> =
            ranges(&param_starts, tables, TableId::Param, TableId::MethodDef)?;
        let type_properties: BTreeMap<u32, Vec<u32>> = map_lists(
            &extra.property_maps,
            tables,
            TableId::Property,
            TableId::PropertyMap,
        )?;
        let type_events: BTreeMap<u32, Vec<u32>> =
            map_lists(&extra.event_maps, tables, TableId::Event, TableId::EventMap)?;
        Ok(Self {
            field_owner: owners(&type_fields),
            method_owner: owners(&type_methods),
            param_owner: owners(&method_params),
            type_fields,
            type_methods,
            method_params,
            type_properties,
            type_events,
        })
    }
}

type Owner = (TableId, u32);

const fn owner_key(reference: RowRef) -> Owner {
    (reference.table, reference.row)
}

#[derive(Debug, Default)]
struct Index {
    constants: BTreeMap<Owner, usize>,
    marshals: BTreeMap<Owner, usize>,
    security: BTreeMap<Owner, Vec<usize>>,
    generic_params: BTreeMap<Owner, Vec<usize>>,
    semantics: BTreeMap<Owner, Vec<usize>>,
    constraints: BTreeMap<u32, Vec<usize>>,
    interface_impls: BTreeMap<u32, Vec<usize>>,
    method_impls: BTreeMap<u32, Vec<usize>>,
    class_layouts: BTreeMap<u32, usize>,
    field_layouts: BTreeMap<u32, usize>,
}

impl Index {
    fn read(tables: &Tables, extra: &Extra) -> Self {
        let mut index: Self = Self::default();
        for (row, constant) in tables.constants.iter().enumerate() {
            if let Some(parent) = constant.parent {
                index.constants.entry(owner_key(parent)).or_insert(row);
            }
        }
        for (row, (parent, _)) in extra.field_marshals.iter().enumerate() {
            if let Some(parent) = parent {
                index.marshals.entry(owner_key(*parent)).or_insert(row);
            }
        }
        for (row, security) in extra.security.iter().enumerate() {
            if let Some(parent) = security.parent {
                index
                    .security
                    .entry(owner_key(parent))
                    .or_default()
                    .push(row);
            }
        }
        for (row, parameter) in tables.generic_params.iter().enumerate() {
            if let Some(owner) = parameter.owner {
                index
                    .generic_params
                    .entry(owner_key(owner))
                    .or_default()
                    .push(row);
            }
        }
        for (row, semantics) in extra.semantics.iter().enumerate() {
            if let Some(association) = semantics.association {
                index
                    .semantics
                    .entry(owner_key(association))
                    .or_default()
                    .push(row);
            }
        }
        for (row, constraint) in extra.constraints.iter().enumerate() {
            index
                .constraints
                .entry(constraint.owner)
                .or_default()
                .push(row);
        }
        for (row, implementation) in tables.interface_impls.iter().enumerate() {
            index
                .interface_impls
                .entry(implementation.class_type)
                .or_default()
                .push(row);
        }
        for (row, implementation) in tables.method_impls.iter().enumerate() {
            index
                .method_impls
                .entry(implementation.class_type)
                .or_default()
                .push(row);
        }
        for (row, layout) in tables.class_layouts.iter().enumerate() {
            index.class_layouts.entry(layout.parent).or_insert(row);
        }
        for (row, (_, field)) in extra.field_layouts.iter().enumerate() {
            index.field_layouts.entry(*field).or_insert(row);
        }
        index
    }
}

#[derive(Debug)]
struct Image<'a> {
    bytes: &'a [u8],
    pe: PeImage,
    clr: ClrHeader,
    root: MetadataRoot,
    tables: Tables,
    extra: Extra,
    members: Membership,
    index: Index,
    enclosing: BTreeMap<u32, u32>,
    strings: &'a [u8],
    blobs: &'a [u8],
    guids: &'a [u8],
    user_strings: &'a [u8],
}

fn heap<'a>(metadata: &'a [u8], root: &MetadataRoot, name: &str) -> Outcome<&'a [u8]> {
    let Some(header): Option<&StreamHeader> = root.streams.get(name) else {
        return Ok(&[]);
    };
    let start: usize = header.offset as usize;
    let end: usize = start.saturating_add(header.size as usize);
    metadata.get(start..end).ok_or_else(|| {
        Fault::malformed(
            Location::MetadataRoot,
            format!("stream {name} lies past the metadata"),
        )
    })
}

impl<'a> Image<'a> {
    fn load(bytes: &'a [u8]) -> Outcome<Self> {
        let pe: PeImage = parse(bytes)?;
        let clr: ClrHeader = parse_clr_header(bytes, &pe)?;
        let root: MetadataRoot = parse_metadata_root(bytes, &pe, &clr)?;
        let metadata: &'a [u8] = metadata_slice(bytes, &pe, &clr, &root)?;
        let (name, header): (&str, StreamHeader) = ["#~", "#-"]
            .into_iter()
            .find_map(|name: &str| {
                root.streams
                    .get(name)
                    .map(|header: &StreamHeader| (name, *header))
            })
            .ok_or_else(|| Fault::malformed(Location::MetadataRoot, "no #~ or #- table stream"))?;
        let tables: Tables = parse_tables(metadata, header)?;
        let stream_info: TableStream = parse_table_stream(metadata, header)?;
        let stream: &'a [u8] = heap(metadata, &root, name)?;
        let reader: TableReader<'a> = TableReader {
            stream,
            spans: table_spans(metadata, header)?,
        };
        let widths: Widths<'_> = Widths {
            heap: HeapWidths::from_flags(stream_info.heap_sizes),
            counts: &stream_info.row_counts,
        };
        let extra: Extra = Extra::read(&reader, &widths)?;
        let members: Membership = Membership::read(&tables, &extra)?;
        let index: Index = Index::read(&tables, &extra);
        let mut enclosing: BTreeMap<u32, u32> = BTreeMap::new();
        for row in &tables.nested_classes {
            enclosing
                .entry(row.nested_class)
                .or_insert(row.enclosing_class);
        }
        Ok(Self {
            bytes,
            strings: heap(metadata, &root, "#Strings")?,
            blobs: heap(metadata, &root, "#Blob")?,
            guids: heap(metadata, &root, "#GUID")?,
            user_strings: heap(metadata, &root, "#US")?,
            pe,
            clr,
            root,
            tables,
            extra,
            members,
            index,
            enclosing,
        })
    }

    fn string(&self, index: u32, location: Location) -> Outcome<String> {
        if index == 0 {
            return Ok(String::new());
        }
        let rest: &[u8] = self
            .strings
            .get(index as usize..)
            .filter(|rest: &&[u8]| !rest.is_empty())
            .ok_or_else(|| {
                Fault::malformed(location, "string index lies past the #Strings heap")
            })?;
        let length: usize = rest
            .iter()
            .position(|byte: &u8| *byte == 0)
            .unwrap_or(rest.len());
        if length > MAX_NAME_BYTES {
            return Err(Fault::Bound {
                what: "name length",
                limit: MAX_NAME_BYTES,
            });
        }
        Ok(String::from_utf8_lossy(&rest[..length]).into_owned())
    }

    fn blob(&self, index: u32, location: Location) -> Outcome<&'a [u8]> {
        if index == 0 {
            return Ok(&[]);
        }
        let start: usize = index as usize;
        let rest: &'a [u8] = self
            .blobs
            .get(start..)
            .filter(|rest: &&[u8]| !rest.is_empty())
            .ok_or_else(|| Fault::malformed(location, "blob index lies past the #Blob heap"))?;
        let (length, consumed): (u32, usize) = decompress_uint(rest)
            .ok_or_else(|| Fault::malformed(location, "blob length is not a compressed integer"))?;
        rest.get(consumed..consumed.saturating_add(length as usize))
            .ok_or_else(|| Fault::malformed(location, "blob runs past the #Blob heap"))
    }

    fn guid(&self, index: u32, location: Location) -> Outcome<Option<String>> {
        if index == 0 {
            return Ok(None);
        }
        let start: usize = (index as usize - 1).saturating_mul(16);
        let bytes: &[u8] = self
            .guids
            .get(start..start.saturating_add(16))
            .ok_or_else(|| Fault::malformed(location, "GUID index lies past the #GUID heap"))?;
        let mut text: String = String::with_capacity(36);
        for (position, byte) in [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
            .iter()
            .filter_map(|index: &usize| bytes.get(*index))
            .enumerate()
        {
            if matches!(position, 4 | 6 | 8 | 10) {
                text.push('-');
            }
            let _: fmt::Result = write!(text, "{byte:02x}");
        }
        Ok(Some(text))
    }

    fn user_string(&self, offset: u32, location: Location) -> Outcome<&'a [u8]> {
        let rest: &'a [u8] = self
            .user_strings
            .get(offset as usize..)
            .filter(|rest: &&[u8]| !rest.is_empty())
            .ok_or_else(|| Fault::malformed(location, "user string lies past the #US heap"))?;
        let (length, consumed): (u32, usize) = decompress_uint(rest).ok_or_else(|| {
            Fault::malformed(location, "user string length is not a compressed integer")
        })?;
        let blob: &'a [u8] = rest
            .get(consumed..consumed.saturating_add(length as usize))
            .ok_or_else(|| Fault::malformed(location, "user string runs past the #US heap"))?;
        Ok(&blob[..blob.len() & !1])
    }

    fn reproducible(&self) -> Outcome<bool> {
        let Some(directory): Option<&DataDirectory> =
            self.pe.data_directories.get(DEBUG_DIRECTORY_INDEX)
        else {
            return Ok(false);
        };
        if directory.size == 0 {
            return Ok(false);
        }
        let size: usize = directory.size as usize;
        if !size.is_multiple_of(DEBUG_ENTRY_SIZE) {
            return Err(Fault::malformed(
                Location::DebugDirectory,
                "size is not a multiple of the 28-byte entry",
            ));
        }
        if size / DEBUG_ENTRY_SIZE > MAX_DEBUG_ENTRIES {
            return Err(Fault::Bound {
                what: "debug directory entries",
                limit: MAX_DEBUG_ENTRIES,
            });
        }
        let entries: &[u8] = self
            .pe
            .slice_at_rva(self.bytes, directory.rva, size)
            .map_err(|_| {
                Fault::malformed(Location::DebugDirectory, "entries lie outside the image")
            })?;
        Ok(entries.chunks_exact(DEBUG_ENTRY_SIZE).any(|entry: &[u8]| {
            entry
                .get(12..16)
                .and_then(|kind: &[u8]| <[u8; 4]>::try_from(kind).ok())
                .is_some_and(|kind: [u8; 4]| u32::from_le_bytes(kind) == DEBUG_TYPE_REPRODUCIBLE)
        }))
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _: fmt::Result = write!(text, "{byte:02X}");
    }
    text
}

fn hex_lower(bytes: &[u8]) -> String {
    hex_upper(bytes).to_ascii_lowercase()
}

fn qualify(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_owned()
    } else {
        format!("{namespace}.{name}")
    }
}

#[derive(Debug)]
struct SigWalk<'b> {
    blob: &'b [u8],
    position: usize,
    location: Location,
}

impl<'b> SigWalk<'b> {
    const fn new(blob: &'b [u8], location: Location) -> Self {
        Self {
            blob,
            position: 0,
            location,
        }
    }

    fn malformed(&self, reason: &str) -> Fault {
        Fault::malformed(self.location, format!("signature {reason}"))
    }

    fn byte(&mut self) -> Outcome<u8> {
        let byte: u8 = *self
            .blob
            .get(self.position)
            .ok_or_else(|| self.malformed("ends early"))?;
        self.position += 1;
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.blob.get(self.position).copied()
    }

    const fn remaining(&self) -> usize {
        self.blob.len().saturating_sub(self.position)
    }

    fn compressed(&mut self) -> Outcome<u32> {
        let rest: &[u8] = self.blob.get(self.position..).unwrap_or(&[]);
        let (value, consumed): (u32, usize) = decompress_uint(rest)
            .ok_or_else(|| self.malformed("holds a bad compressed integer"))?;
        self.position += consumed;
        Ok(value)
    }

    fn compressed_signed(&mut self) -> Outcome<i32> {
        let rest: &[u8] = self.blob.get(self.position..).unwrap_or(&[]);
        let (value, consumed): (u32, usize) = decompress_uint(rest)
            .ok_or_else(|| self.malformed("holds a bad compressed integer"))?;
        self.position += consumed;
        let magnitude: i32 = (value >> 1) as i32;
        if value & 1 == 0 {
            return Ok(magnitude);
        }
        let mask: u32 = match consumed {
            1 => 0xFFFF_FFC0,
            2 => 0xFFFF_E000,
            _ => 0xF000_0000,
        };
        Ok(((value >> 1) | mask) as i32)
    }

    fn count(&mut self) -> Outcome<usize> {
        let count: usize = self.compressed()? as usize;
        if count > self.remaining() {
            return Err(self.malformed("declares more entries than it holds"));
        }
        Ok(count)
    }
}

#[derive(Debug)]
struct SigText {
    prefix: String,
    ret: Rc<str>,
    arity: u32,
    params: Vec<Rc<str>>,
    required: usize,
}

impl SigText {
    fn arity(&self) -> String {
        if self.arity == 0 {
            String::new()
        } else {
            format!("``{}", self.arity)
        }
    }

    fn parameters(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(self.params.len() + 1);
        for (index, param) in self.params.iter().enumerate() {
            if index == self.required {
                parts.push("...");
            }
            parts.push(param.as_ref());
        }
        format!("({})", parts.join(", "))
    }

    fn standalone(&self) -> String {
        format!(
            "{}{}{}{}",
            self.prefix,
            self.ret,
            self.arity(),
            self.parameters()
        )
    }

    fn member(&self, owner: &str, name: &str) -> String {
        format!(
            "{}{} {owner}::{name}{}{}",
            self.prefix,
            self.ret,
            self.arity(),
            self.parameters()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NormalOperand {
    Value(OperandValue),
    Name(Rc<str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalHandler {
    kind: ExceptionClauseKind,
    try_offset: u32,
    try_length: u32,
    handler_offset: u32,
    handler_length: u32,
    handler: NormalOperand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalBody {
    max_stack: u16,
    init_locals: bool,
    locals: Rc<str>,
    code: Vec<(u16, NormalOperand)>,
    handlers: Vec<NormalHandler>,
}

#[derive(Debug)]
struct RawBody<'a> {
    raw: &'a [u8],
    body: MethodBody,
}

#[derive(Debug)]
struct Namer<'i, 'a> {
    image: &'i Image<'a>,
    type_defs: BTreeMap<u32, Rc<str>>,
    type_refs: BTreeMap<u32, Rc<str>>,
    type_specs: BTreeMap<u32, Rc<str>>,
    method_keys: BTreeMap<u32, Rc<str>>,
    operands: BTreeMap<u32, Rc<str>>,
    pending: BTreeSet<(TableId, u32)>,
    depth: usize,
    rendered: usize,
    il_bytes: usize,
}

impl<'i, 'a> Namer<'i, 'a> {
    const fn new(image: &'i Image<'a>) -> Self {
        Self {
            image,
            type_defs: BTreeMap::new(),
            type_refs: BTreeMap::new(),
            type_specs: BTreeMap::new(),
            method_keys: BTreeMap::new(),
            operands: BTreeMap::new(),
            pending: BTreeSet::new(),
            depth: 0,
            rendered: 0,
            il_bytes: 0,
        }
    }

    const fn budget(&mut self, length: usize) -> Outcome<()> {
        self.rendered = self.rendered.saturating_add(length);
        if self.rendered > MAX_RENDERED_BYTES {
            return Err(Fault::Bound {
                what: "rendered text total",
                limit: MAX_RENDERED_BYTES,
            });
        }
        Ok(())
    }

    const fn account(&mut self, length: usize) -> Outcome<()> {
        if length > MAX_NAME_BYTES {
            return Err(Fault::Bound {
                what: "rendered name length",
                limit: MAX_NAME_BYTES,
            });
        }
        self.budget(length)
    }

    fn charge(&mut self, text: String) -> Outcome<Rc<str>> {
        self.account(text.len())?;
        Ok(Rc::from(text))
    }

    fn enter(&mut self, table: TableId, rid: u32) -> Outcome<()> {
        if self.pending.len() >= MAX_TYPE_NESTING {
            return Err(Fault::Bound {
                what: "type name nesting",
                limit: MAX_TYPE_NESTING,
            });
        }
        if !self.pending.insert((table, rid)) {
            return Err(Fault::malformed(
                Location::row(table, rid),
                "type name refers to itself",
            ));
        }
        Ok(())
    }

    fn type_def(&mut self, rid: u32) -> Outcome<Rc<str>> {
        if let Some(name) = self.type_defs.get(&rid) {
            return Ok(Rc::clone(name));
        }
        let location: Location = Location::row(TableId::TypeDef, rid);
        let row: TypeDefRow = row_at(
            &self.image.tables.type_defs,
            rid,
            location,
            "type definition",
        )?;
        let own: String = qualify(
            &self.image.string(row.namespace, location)?,
            &self.image.string(row.name, location)?,
        );
        let text: String = match self.image.enclosing.get(&rid).copied() {
            Some(outer) => {
                self.enter(TableId::TypeDef, rid)?;
                let outer_name: Outcome<Rc<str>> = self.type_def(outer);
                self.pending.remove(&(TableId::TypeDef, rid));
                format!("{}/{own}", outer_name?)
            }
            None => own,
        };
        let name: Rc<str> = self.charge(text)?;
        self.type_defs.insert(rid, Rc::clone(&name));
        Ok(name)
    }

    fn type_ref(&mut self, rid: u32) -> Outcome<Rc<str>> {
        if let Some(name) = self.type_refs.get(&rid) {
            return Ok(Rc::clone(name));
        }
        let location: Location = Location::row(TableId::TypeRef, rid);
        let row: crate::tables::TypeRefRow = row_at(
            &self.image.tables.type_refs,
            rid,
            location,
            "type reference",
        )?;
        let own: String = qualify(
            &self.image.string(row.namespace, location)?,
            &self.image.string(row.name, location)?,
        );
        let text: String = match row.resolution_scope {
            None => format!("[*]{own}"),
            Some(RowRef {
                table: TableId::Module,
                ..
            }) => format!("[.module]{own}"),
            Some(RowRef {
                table: TableId::ModuleRef,
                row: scope,
            }) => format!("[.module {}]{own}", self.module_ref(scope)?),
            Some(RowRef {
                table: TableId::AssemblyRef,
                row: scope,
            }) => format!("[{}]{own}", self.assembly_ref(scope)?),
            Some(RowRef {
                table: TableId::TypeRef,
                row: outer,
            }) => {
                self.enter(TableId::TypeRef, rid)?;
                let outer_name: Outcome<Rc<str>> = self.type_ref(outer);
                self.pending.remove(&(TableId::TypeRef, rid));
                format!("{}/{own}", outer_name?)
            }
            Some(_) => {
                return Err(Fault::malformed(
                    location,
                    "resolution scope names a foreign table",
                ));
            }
        };
        let name: Rc<str> = self.charge(text)?;
        self.type_refs.insert(rid, Rc::clone(&name));
        Ok(name)
    }

    fn type_spec(&mut self, rid: u32) -> Outcome<Rc<str>> {
        if let Some(name) = self.type_specs.get(&rid) {
            return Ok(Rc::clone(name));
        }
        let location: Location = Location::row(TableId::TypeSpec, rid);
        let row: crate::tables::TypeSpecRow = row_at(
            &self.image.tables.type_specs,
            rid,
            location,
            "type specification",
        )?;
        let blob: &[u8] = self.image.blob(row.signature, location)?;
        self.enter(TableId::TypeSpec, rid)?;
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        let rendered: Outcome<Rc<str>> = self.sig_type(&mut walk);
        self.pending.remove(&(TableId::TypeSpec, rid));
        let name: Rc<str> = rendered?;
        self.budget(name.len())?;
        self.type_specs.insert(rid, Rc::clone(&name));
        Ok(name)
    }

    fn module_ref(&self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::ModuleRef, rid);
        let row: crate::tables::ModuleRefRow = row_at(
            &self.image.tables.module_refs,
            rid,
            location,
            "module reference",
        )?;
        self.image.string(row.name, location)
    }

    fn assembly_ref(&self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::AssemblyRef, rid);
        let row: crate::tables::AssemblyRefRow = row_at(
            &self.image.tables.assembly_refs,
            rid,
            location,
            "assembly reference",
        )?;
        self.image.string(row.name, location)
    }

    fn type_token(&mut self, reference: RowRef, location: Location) -> Outcome<Rc<str>> {
        match reference.table {
            TableId::TypeDef => self.type_def(reference.row),
            TableId::TypeRef => self.type_ref(reference.row),
            TableId::TypeSpec => self.type_spec(reference.row),
            _ => Err(Fault::malformed(
                location,
                "type index names a foreign table",
            )),
        }
    }

    fn optional_type(&mut self, reference: Option<RowRef>, location: Location) -> Outcome<Rc<str>> {
        reference.map_or_else(
            || Ok(Rc::from("none")),
            |reference: RowRef| self.type_token(reference, location),
        )
    }

    fn sig_type_handle(&mut self, walk: &mut SigWalk<'_>) -> Outcome<Rc<str>> {
        let coded: u32 = walk.compressed()?;
        let row: u32 = coded >> 2;
        if row == 0 {
            return Err(walk.malformed("names a null type"));
        }
        let table: TableId = match coded & 0x3 {
            0 => TableId::TypeDef,
            1 => TableId::TypeRef,
            2 => TableId::TypeSpec,
            _ => return Err(walk.malformed("holds a bad type tag")),
        };
        self.type_token(RowRef { table, row }, walk.location)
    }

    fn sig_type(&mut self, walk: &mut SigWalk<'_>) -> Outcome<Rc<str>> {
        if self.depth >= MAX_SIGNATURE_DEPTH {
            return Err(Fault::Bound {
                what: "signature depth",
                limit: MAX_SIGNATURE_DEPTH,
            });
        }
        let outermost: bool = self.depth == 0;
        self.depth += 1;
        let rendered: Outcome<Rc<str>> = self.sig_type_inner(walk);
        self.depth -= 1;
        let rendered: Rc<str> = rendered?;
        if outermost {
            self.account(rendered.len())?;
        } else if rendered.len() > MAX_NAME_BYTES {
            return Err(Fault::Bound {
                what: "rendered name length",
                limit: MAX_NAME_BYTES,
            });
        }
        Ok(rendered)
    }

    fn sig_type_inner(&mut self, walk: &mut SigWalk<'_>) -> Outcome<Rc<str>> {
        let code: u32 = walk.compressed()?;
        let text: String = match code {
            0x01 => return Ok(Rc::from("void")),
            0x02 => return Ok(Rc::from("bool")),
            0x03 => return Ok(Rc::from("char")),
            0x04 => return Ok(Rc::from("int8")),
            0x05 => return Ok(Rc::from("uint8")),
            0x06 => return Ok(Rc::from("int16")),
            0x07 => return Ok(Rc::from("uint16")),
            0x08 => return Ok(Rc::from("int32")),
            0x09 => return Ok(Rc::from("uint32")),
            0x0A => return Ok(Rc::from("int64")),
            0x0B => return Ok(Rc::from("uint64")),
            0x0C => return Ok(Rc::from("float32")),
            0x0D => return Ok(Rc::from("float64")),
            0x0E => return Ok(Rc::from("string")),
            0x16 => return Ok(Rc::from("typedref")),
            0x18 => return Ok(Rc::from("native int")),
            0x19 => return Ok(Rc::from("native uint")),
            0x1C => return Ok(Rc::from("object")),
            0x0F => format!("{}*", self.sig_type(walk)?),
            0x10 => format!("{}&", self.sig_type(walk)?),
            0x1D => format!("{}[]", self.sig_type(walk)?),
            0x45 => format!("{} pinned", self.sig_type(walk)?),
            0x11 | 0x12 => return self.sig_type_handle(walk),
            0x13 => format!("!{}", walk.compressed()?),
            0x1E => format!("!!{}", walk.compressed()?),
            0x14 => self.array_type(walk)?,
            0x15 => {
                let kind: u32 = walk.compressed()?;
                if kind != 0x11 && kind != 0x12 {
                    return Err(
                        walk.malformed("instantiates a type that is not a class or value type")
                    );
                }
                let base: Rc<str> = self.sig_type_handle(walk)?;
                let count: usize = walk.count()?;
                if count == 0 {
                    return Err(walk.malformed("instantiates a generic type with no arguments"));
                }
                let mut arguments: Vec<Rc<str>> = Vec::with_capacity(count);
                for _ in 0..count {
                    arguments.push(self.sig_type(walk)?);
                }
                let joined: Vec<&str> = arguments.iter().map(AsRef::as_ref).collect();
                format!("{base}<{}>", joined.join(", "))
            }
            0x1B => format!("method {}", self.method_sig(walk)?.standalone()),
            0x1F | 0x20 => {
                let modifier: Rc<str> = self.sig_type_handle(walk)?;
                let inner: Rc<str> = self.sig_type(walk)?;
                let kind: &str = if code == 0x1F { "modreq" } else { "modopt" };
                format!("{inner} {kind}({modifier})")
            }
            _ => return Err(walk.malformed("holds an unknown element type")),
        };
        Ok(Rc::from(text))
    }

    fn array_type(&mut self, walk: &mut SigWalk<'_>) -> Outcome<String> {
        let element: Rc<str> = self.sig_type(walk)?;
        let rank: u32 = walk.compressed()?;
        if rank > MAX_ARRAY_RANK {
            return Err(Fault::Bound {
                what: "array rank",
                limit: MAX_ARRAY_RANK as usize,
            });
        }
        let size_count: usize = walk.count()?;
        let mut sizes: Vec<u32> = Vec::with_capacity(size_count);
        for _ in 0..size_count {
            sizes.push(walk.compressed()?);
        }
        let bound_count: usize = walk.count()?;
        let mut bounds: Vec<i32> = Vec::with_capacity(bound_count);
        for _ in 0..bound_count {
            bounds.push(walk.compressed_signed()?);
        }
        let mut dimensions: Vec<String> = Vec::with_capacity(rank as usize);
        for index in 0..rank as usize {
            let lower: String = bounds
                .get(index)
                .map(ToString::to_string)
                .unwrap_or_default();
            let size: String = sizes
                .get(index)
                .map(ToString::to_string)
                .unwrap_or_default();
            dimensions.push(format!("{lower}:{size}"));
        }
        Ok(format!("{element}[{}]", dimensions.join(",")))
    }

    fn method_sig(&mut self, walk: &mut SigWalk<'_>) -> Outcome<SigText> {
        let header: u8 = walk.byte()?;
        let mut prefix: String = String::new();
        if header & 0x20 != 0 {
            prefix.push_str("instance ");
        }
        if header & 0x40 != 0 {
            prefix.push_str("explicit ");
        }
        prefix.push_str(match header & 0x0F {
            0 | 8 => "",
            1 => "unmanaged cdecl ",
            2 => "unmanaged stdcall ",
            3 => "unmanaged thiscall ",
            4 => "unmanaged fastcall ",
            5 => "vararg ",
            9 => "unmanaged ",
            _ => return Err(walk.malformed("is not a method or property signature")),
        });
        let arity: u32 = if header & 0x10 != 0 {
            walk.compressed()?
        } else {
            0
        };
        let count: usize = walk.count()?;
        let ret: Rc<str> = self.sig_type(walk)?;
        let mut params: Vec<Rc<str>> = Vec::with_capacity(count);
        let mut required: Option<usize> = None;
        for index in 0..count {
            if required.is_none() && walk.peek() == Some(0x41) {
                walk.position += 1;
                required = Some(index);
            }
            params.push(self.sig_type(walk)?);
        }
        Ok(SigText {
            prefix,
            ret,
            arity,
            params,
            required: required.unwrap_or(count),
        })
    }

    fn method_blob(&mut self, index: u32, location: Location) -> Outcome<SigText> {
        let blob: &[u8] = self.image.blob(index, location)?;
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        self.method_sig(&mut walk)
    }

    fn field_blob(&mut self, index: u32, location: Location) -> Outcome<Rc<str>> {
        let blob: &[u8] = self.image.blob(index, location)?;
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        if walk.byte()? & 0x0F != 0x06 {
            return Err(walk.malformed("is not a field signature"));
        }
        self.sig_type(&mut walk)
    }

    fn local_blob(&mut self, blob: &[u8], location: Location) -> Outcome<String> {
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        if walk.byte()? & 0x0F != 0x07 {
            return Err(walk.malformed("is not a local variable signature"));
        }
        let count: usize = walk.count()?;
        let mut locals: Vec<Rc<str>> = Vec::with_capacity(count);
        for _ in 0..count {
            locals.push(self.sig_type(&mut walk)?);
        }
        let joined: Vec<&str> = locals.iter().map(AsRef::as_ref).collect();
        Ok(format!("[{}]", joined.join(", ")))
    }

    fn method_owner(&mut self, rid: u32) -> Outcome<Rc<str>> {
        let owner: u32 = self
            .image
            .members
            .method_owner
            .get(&rid)
            .copied()
            .ok_or_else(|| {
                Fault::malformed(
                    Location::row(TableId::MethodDef, rid),
                    "method lies outside every type's method list",
                )
            })?;
        self.type_def(owner)
    }

    fn method_key(&mut self, rid: u32) -> Outcome<Rc<str>> {
        if let Some(key) = self.method_keys.get(&rid) {
            return Ok(Rc::clone(key));
        }
        let location: Location = Location::row(TableId::MethodDef, rid);
        let row: crate::tables::MethodDefRow =
            row_at(&self.image.tables.methods, rid, location, "method")?;
        let owner: Rc<str> = self.method_owner(rid)?;
        let name: String = self.image.string(row.name, location)?;
        let signature: SigText = self.method_blob(row.signature, location)?;
        let key: Rc<str> = self.charge(signature.member(&owner, &name))?;
        self.method_keys.insert(rid, Rc::clone(&key));
        Ok(key)
    }

    fn field_key(&mut self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::Field, rid);
        let row: crate::tables::FieldRow =
            row_at(&self.image.tables.fields, rid, location, "field")?;
        let owner: u32 = self
            .image
            .members
            .field_owner
            .get(&rid)
            .copied()
            .ok_or_else(|| {
                Fault::malformed(location, "field lies outside every type's field list")
            })?;
        let owner_name: Rc<str> = self.type_def(owner)?;
        Ok(format!(
            "{owner_name}::{}",
            self.image.string(row.name, location)?
        ))
    }

    fn field_member(&mut self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::Field, rid);
        let signature: u32 = row_at(&self.image.tables.fields, rid, location, "field")?.signature;
        let field_type: Rc<str> = self.field_blob(signature, location)?;
        Ok(format!("{field_type} {}", self.field_key(rid)?))
    }

    fn member_ref_parent(&mut self, parent: Option<RowRef>, location: Location) -> Outcome<String> {
        match parent {
            Some(
                reference @ RowRef {
                    table: TableId::TypeDef | TableId::TypeRef | TableId::TypeSpec,
                    ..
                },
            ) => Ok(self.type_token(reference, location)?.to_string()),
            Some(RowRef {
                table: TableId::ModuleRef,
                row,
            }) => Ok(format!("[.module {}]", self.module_ref(row)?)),
            Some(RowRef {
                table: TableId::MethodDef,
                row,
            }) => Ok(self.method_key(row)?.to_string()),
            _ => Err(Fault::malformed(location, "member reference has no parent")),
        }
    }

    fn member_ref(&mut self, rid: u32) -> Outcome<(String, bool)> {
        let location: Location = Location::row(TableId::MemberRef, rid);
        let row: crate::tables::MemberRefRow = row_at(
            &self.image.tables.member_refs,
            rid,
            location,
            "member reference",
        )?;
        let parent: String = self.member_ref_parent(row.parent, location)?;
        let name: String = self.image.string(row.name, location)?;
        let blob: &[u8] = self.image.blob(row.signature, location)?;
        if blob
            .first()
            .is_some_and(|header: &u8| header & 0x0F == 0x06)
        {
            let field_type: Rc<str> = self.field_blob(row.signature, location)?;
            return Ok((format!("{field_type} {parent}::{name}"), true));
        }
        let signature: SigText = self.method_blob(row.signature, location)?;
        Ok((signature.member(&parent, &name), false))
    }

    fn method_ref(&mut self, reference: Option<RowRef>, location: Location) -> Outcome<String> {
        match reference {
            Some(RowRef {
                table: TableId::MethodDef,
                row,
            }) => Ok(self.method_key(row)?.to_string()),
            Some(RowRef {
                table: TableId::MemberRef,
                row,
            }) => Ok(self.member_ref(row)?.0),
            _ => Err(Fault::malformed(location, "method index names no method")),
        }
    }

    fn method_spec(&mut self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::MethodSpec, rid);
        let row: crate::tables::MethodSpecRow = row_at(
            &self.image.tables.method_specs,
            rid,
            location,
            "method specification",
        )?;
        let method: String = self.method_ref(row.method, location)?;
        let blob: &[u8] = self.image.blob(row.instantiation, location)?;
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        if walk.byte()? & 0x0F != 0x0A {
            return Err(walk.malformed("is not a generic method instantiation"));
        }
        let count: usize = walk.count()?;
        let mut arguments: Vec<Rc<str>> = Vec::with_capacity(count);
        for _ in 0..count {
            arguments.push(self.sig_type(&mut walk)?);
        }
        let joined: Vec<&str> = arguments.iter().map(AsRef::as_ref).collect();
        Ok(format!("{method}<{}>", joined.join(", ")))
    }

    fn standalone_sig(&mut self, rid: u32) -> Outcome<String> {
        let location: Location = Location::row(TableId::StandAloneSig, rid);
        let signature: u32 = row_at(
            &self.image.tables.standalone_sigs,
            rid,
            location,
            "standalone signature",
        )?
        .signature;
        let blob: &[u8] = self.image.blob(signature, location)?;
        if blob
            .first()
            .is_some_and(|header: &u8| header & 0x0F == 0x07)
        {
            return self.local_blob(blob, location);
        }
        let mut walk: SigWalk<'_> = SigWalk::new(blob, location);
        Ok(self.method_sig(&mut walk)?.standalone())
    }

    fn operand(&mut self, token: u32, location: Location) -> Outcome<Rc<str>> {
        if let Some(text) = self.operands.get(&token) {
            return Ok(Rc::clone(text));
        }
        let rid: u32 = token & 0x00FF_FFFF;
        let text: String = if token >> 24 == USER_STRING_TABLE {
            format!(
                "string {}",
                hex_upper(self.image.user_string(rid, location)?)
            )
        } else {
            match TableId::from_index((token >> 24) as u8) {
                Some(table @ (TableId::TypeDef | TableId::TypeRef | TableId::TypeSpec)) => {
                    format!(
                        "type {}",
                        self.type_token(RowRef { table, row: rid }, location)?
                    )
                }
                Some(TableId::MethodDef) => format!("method {}", self.method_key(rid)?),
                Some(TableId::Field) => format!("field {}", self.field_member(rid)?),
                Some(TableId::MemberRef) => {
                    let (text, is_field): (String, bool) = self.member_ref(rid)?;
                    format!("{} {text}", if is_field { "field" } else { "method" })
                }
                Some(TableId::MethodSpec) => format!("methodspec {}", self.method_spec(rid)?),
                Some(TableId::StandAloneSig) => format!("sig {}", self.standalone_sig(rid)?),
                _ => format!("token 0x{token:08X}"),
            }
        };
        let text: Rc<str> = self.charge(text)?;
        self.operands.insert(token, Rc::clone(&text));
        Ok(text)
    }

    fn raw_body(&mut self, rid: u32, rva: u32) -> Outcome<RawBody<'a>> {
        let location: Location = Location::row(TableId::MethodDef, rid);
        let image: &Image<'a> = self.image;
        let offset: usize = image
            .pe
            .rva_to_offset(rva)
            .ok_or_else(|| Fault::malformed(location, "method body RVA maps to no section"))?;
        let bytes: &'a [u8] = image
            .bytes
            .get(offset..)
            .ok_or_else(|| Fault::malformed(location, "method body lies past the image"))?;
        let extent: usize = method_body_extent(bytes)
            .map_err(|error: Error| Fault::malformed(location, format!("method body: {error}")))?
            .consumed_bytes;
        self.il_bytes = self.il_bytes.saturating_add(extent);
        if self.il_bytes > MAX_IL_BYTES {
            return Err(Fault::Bound {
                what: "method body bytes",
                limit: MAX_IL_BYTES,
            });
        }
        let raw: &'a [u8] = bytes
            .get(..extent)
            .ok_or_else(|| Fault::malformed(location, "method body lies past the image"))?;
        let body: MethodBody = parse_method_body(raw)
            .map_err(|error: Error| Fault::malformed(location, format!("method body: {error}")))?;
        Ok(RawBody { raw, body })
    }

    fn normalize(&mut self, rid: u32, body: &MethodBody) -> Outcome<NormalBody> {
        let location: Location = Location::row(TableId::MethodDef, rid);
        let locals: Rc<str> = match body.local_var_sig_tok {
            0 => Rc::from("none"),
            token if token >> 24 == u32::from(TableId::StandAloneSig.index()) => {
                let text: String = self.standalone_sig(token & 0x00FF_FFFF)?;
                self.charge(text)?
            }
            _ => {
                return Err(Fault::malformed(
                    location,
                    "local variable signature token names a foreign table",
                ));
            }
        };
        let mut code: Vec<(u16, NormalOperand)> = Vec::with_capacity(body.instructions.len());
        for instruction in &body.instructions {
            code.push((
                instruction.opcode,
                self.normal_operand(instruction, location)?,
            ));
        }
        let mut handlers: Vec<NormalHandler> = Vec::with_capacity(body.exception_clauses.len());
        for clause in &body.exception_clauses {
            handlers.push(self.normal_handler(clause, location)?);
        }
        Ok(NormalBody {
            max_stack: body.max_stack,
            init_locals: body.init_locals,
            locals,
            code,
            handlers,
        })
    }

    fn normal_operand(
        &mut self,
        instruction: &Instruction,
        location: Location,
    ) -> Outcome<NormalOperand> {
        match &instruction.operand {
            OperandValue::Token(token) => Ok(NormalOperand::Name(self.operand(*token, location)?)),
            other => Ok(NormalOperand::Value(other.clone())),
        }
    }

    fn normal_handler(
        &mut self,
        clause: &ExceptionClause,
        location: Location,
    ) -> Outcome<NormalHandler> {
        let handler: NormalOperand = match clause.kind {
            ExceptionClauseKind::Catch => {
                let token: u32 = clause.class_token_or_filter;
                let table: Option<TableId> = TableId::from_index((token >> 24) as u8);
                match table {
                    Some(table @ (TableId::TypeDef | TableId::TypeRef | TableId::TypeSpec)) => {
                        NormalOperand::Name(self.type_token(
                            RowRef {
                                table,
                                row: token & 0x00FF_FFFF,
                            },
                            location,
                        )?)
                    }
                    _ => {
                        return Err(Fault::malformed(location, "catch clause names no type"));
                    }
                }
            }
            ExceptionClauseKind::Filter => {
                NormalOperand::Value(OperandValue::I64(i64::from(clause.class_token_or_filter)))
            }
            ExceptionClauseKind::Finally | ExceptionClauseKind::Fault => {
                NormalOperand::Value(OperandValue::None)
            }
        };
        Ok(NormalHandler {
            kind: clause.kind,
            try_offset: clause.try_offset,
            try_length: clause.try_length,
            handler_offset: clause.handler_offset,
            handler_length: clause.handler_length,
            handler,
        })
    }
}

#[derive(Debug, Clone)]
struct Entry {
    key: String,
    group: String,
    signature: String,
    location: Location,
    aspects: Vec<(Aspect, String)>,
    body: Option<BodyRef>,
}

#[derive(Debug, Clone, Copy)]
struct BodyRef {
    rid: u32,
    rva: Option<u32>,
}

#[derive(Debug, Clone)]
struct AttributeEntry {
    group: String,
    value: String,
    location: Location,
}

#[derive(Debug)]
struct Facts {
    identity: BTreeMap<IdentityField, (String, Option<Location>)>,
    entities: BTreeMap<Entity, Vec<Entry>>,
    attributes: Vec<AttributeEntry>,
    summary: AssemblySummary,
}

fn flags16(value: u16) -> String {
    format!("0x{value:04X}")
}

fn flags32(value: u32) -> String {
    format!("0x{value:08X}")
}

fn sorted_list(mut items: Vec<String>) -> String {
    items.sort();
    format!("[{}]", items.join(", "))
}

fn row_at<T: Copy>(rows: &[T], rid: u32, location: Location, what: &str) -> Outcome<T> {
    rid.checked_sub(1)
        .and_then(|index: u32| rows.get(index as usize))
        .copied()
        .ok_or_else(|| Fault::malformed(location, format!("{what} does not exist")))
}

fn rows_of<T>(rows: Option<&Vec<T>>) -> &[T] {
    rows.map_or(&[], Vec::as_slice)
}

fn rid_of(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

impl Facts {
    fn read(namer: &mut Namer<'_, '_>) -> Outcome<Self> {
        let image: &Image<'_> = namer.image;
        let mut facts: Self = Self {
            identity: BTreeMap::new(),
            entities: BTreeMap::new(),
            attributes: Vec::new(),
            summary: AssemblySummary {
                name: None,
                version: None,
                mvid: None,
                types: image.tables.type_defs.len(),
                methods: image.tables.methods.len(),
                fields: image.tables.fields.len(),
            },
        };
        for entity in [
            Entity::AssemblyRef,
            Entity::Type,
            Entity::Field,
            Entity::Method,
            Entity::Property,
            Entity::Event,
            Entity::Pinvoke,
            Entity::Resource,
        ] {
            facts.entities.insert(entity, Vec::new());
        }
        facts.read_identity(namer)?;
        facts.read_assembly_refs(namer)?;
        let mut property_keys: BTreeMap<u32, String> = BTreeMap::new();
        let mut event_keys: BTreeMap<u32, String> = BTreeMap::new();
        for index in 0..image.tables.type_defs.len() {
            facts.read_type(namer, rid_of(index), &mut property_keys, &mut event_keys)?;
        }
        facts.read_pinvokes(namer)?;
        facts.read_resources(namer)?;
        facts.read_attributes(namer, &property_keys, &event_keys)?;
        Ok(facts)
    }

    fn push(&mut self, namer: &mut Namer<'_, '_>, entity: Entity, entry: Entry) -> Outcome<()> {
        let size: usize = entry.aspects.iter().fold(
            entry.key.len() + entry.group.len() + entry.signature.len(),
            |total: usize, (_, value): &(Aspect, String)| total.saturating_add(value.len()),
        );
        namer.budget(size)?;
        self.entities.entry(entity).or_default().push(entry);
        Ok(())
    }

    fn set(&mut self, field: IdentityField, value: String, location: Option<Location>) {
        self.identity.insert(field, (value, location));
    }

    fn security(namer: &Namer<'_, '_>, parent: RowRef) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let mut items: Vec<String> = Vec::new();
        for index in rows_of(image.index.security.get(&owner_key(parent))) {
            let row: &SecurityRow = &image.extra.security[*index];
            let location: Location = Location::row(TableId::DeclSecurity, rid_of(*index));
            items.push(format!(
                "{}:{}",
                flags16(row.action),
                hex_upper(image.blob(row.permission_set, location)?)
            ));
        }
        Ok(sorted_list(items))
    }

    fn constant(namer: &Namer<'_, '_>, parent: RowRef) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let Some(index): Option<usize> = image.index.constants.get(&owner_key(parent)).copied()
        else {
            return Ok("none".to_owned());
        };
        let row: &crate::tables::ConstantRow = &image.tables.constants[index];
        let location: Location = Location::row(TableId::Constant, rid_of(index));
        Ok(format!(
            "{:02X}:{}",
            row.element_type,
            hex_upper(image.blob(row.value, location)?)
        ))
    }

    fn marshal(namer: &Namer<'_, '_>, parent: RowRef) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let Some(index): Option<usize> = image.index.marshals.get(&owner_key(parent)).copied()
        else {
            return Ok("none".to_owned());
        };
        let blob: u32 = image.extra.field_marshals[index].1;
        if blob == 0 {
            return Ok("none".to_owned());
        }
        let location: Location = Location::row(TableId::FieldMarshal, rid_of(index));
        Ok(hex_upper(image.blob(blob, location)?))
    }

    fn generic_parameters(namer: &mut Namer<'_, '_>, owner: RowRef) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let mut items: Vec<String> = Vec::new();
        for index in rows_of(image.index.generic_params.get(&owner_key(owner))) {
            let row: &crate::tables::GenericParamRow = &image.tables.generic_params[*index];
            let rid: u32 = rid_of(*index);
            let location: Location = Location::row(TableId::GenericParam, rid);
            let mut constraints: Vec<String> = Vec::new();
            for constraint_index in rows_of(image.index.constraints.get(&rid)) {
                let constraint_location: Location =
                    Location::row(TableId::GenericParamConstraint, rid_of(*constraint_index));
                let reference: RowRef = image.extra.constraints[*constraint_index]
                    .constraint
                    .ok_or_else(|| {
                        Fault::malformed(constraint_location, "constraint names no type")
                    })?;
                constraints.push(
                    namer
                        .type_token(reference, constraint_location)?
                        .to_string(),
                );
            }
            constraints.sort();
            items.push(format!(
                "{}/{}/[{}]",
                image.string(row.name, location)?,
                flags16(row.flags),
                constraints.join(", ")
            ));
        }
        Ok(format!("[{}]", items.join(", ")))
    }

    fn read_identity(&mut self, namer: &Namer<'_, '_>) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        if let Some(assembly) = image.tables.assembly {
            let location: Location = Location::row(TableId::Assembly, 1);
            let row: Option<Location> = Some(location);
            let name: String = image.string(assembly.name, location)?;
            let version: String = format!(
                "{}.{}.{}.{}",
                assembly.major, assembly.minor, assembly.build, assembly.revision
            );
            let culture: String = image.string(assembly.culture, location)?;
            let key: &[u8] = image.blob(assembly.public_key, location)?;
            let token: String = if key.is_empty() {
                "null".to_owned()
            } else {
                let digest: [u8; 20] = Sha1::digest(key).into();
                let mut tail: Vec<u8> = digest[12..].to_vec();
                tail.reverse();
                hex_lower(&tail)
            };
            self.summary.name = Some(name.clone());
            self.summary.version = Some(version.clone());
            self.set(IdentityField::Name, name, row);
            self.set(IdentityField::Version, version, row);
            self.set(
                IdentityField::Culture,
                if culture.is_empty() {
                    "neutral".to_owned()
                } else {
                    culture
                },
                row,
            );
            self.set(IdentityField::Flags, flags32(assembly.flags), row);
            self.set(
                IdentityField::HashAlgorithm,
                flags32(assembly.hash_alg_id),
                row,
            );
            self.set(IdentityField::PublicKeyToken, token, row);
            self.set(
                IdentityField::Security,
                Self::security(
                    namer,
                    RowRef {
                        table: TableId::Assembly,
                        row: 1,
                    },
                )?,
                row,
            );
            let (framework, framework_row): (String, Option<Location>) =
                Self::target_framework(namer)?;
            self.set(IdentityField::TargetFramework, framework, framework_row);
        }
        let module: &crate::tables::ModuleRow = image
            .tables
            .modules
            .first()
            .ok_or_else(|| Fault::malformed(Location::MetadataRoot, "no Module row"))?;
        let module_location: Location = Location::row(TableId::Module, 1);
        self.set(
            IdentityField::Module,
            image.string(module.name, module_location)?,
            Some(module_location),
        );
        let mvid: Option<String> = image.guid(module.mvid, module_location)?;
        self.summary.mvid.clone_from(&mvid);
        self.set(
            IdentityField::Mvid,
            mvid.unwrap_or_else(|| "none".to_owned()),
            Some(module_location),
        );
        self.set(
            IdentityField::MetadataVersion,
            image.root.version.clone(),
            Some(Location::MetadataRoot),
        );
        self.set(
            IdentityField::PeTimestamp,
            flags32(image.pe.timestamp),
            Some(Location::CoffHeader),
        );
        self.set(
            IdentityField::Machine,
            flags16(image.pe.machine),
            Some(Location::CoffHeader),
        );
        self.set(
            IdentityField::ClrFlags,
            flags32(image.clr.flags),
            Some(Location::CliHeader),
        );
        self.set(
            IdentityField::Reproducible,
            if image.reproducible()? { "yes" } else { "no" }.to_owned(),
            Some(Location::DebugDirectory),
        );
        Ok(())
    }

    fn attribute_type_names(
        namer: &Namer<'_, '_>,
        constructor: Option<RowRef>,
        location: Location,
    ) -> Outcome<Option<(String, String)>> {
        let image: &Image<'_> = namer.image;
        let owner: Option<RowRef> = match constructor {
            Some(RowRef {
                table: TableId::MethodDef,
                row,
            }) => image
                .members
                .method_owner
                .get(&row)
                .map(|owner: &u32| RowRef {
                    table: TableId::TypeDef,
                    row: *owner,
                }),
            Some(RowRef {
                table: TableId::MemberRef,
                row,
            }) => image
                .tables
                .member_refs
                .get((row as usize).wrapping_sub(1))
                .and_then(|member: &crate::tables::MemberRefRow| member.parent),
            _ => {
                return Err(Fault::malformed(
                    location,
                    "attribute constructor names no method",
                ));
            }
        };
        match owner {
            Some(RowRef {
                table: TableId::TypeRef,
                row,
            }) => {
                let type_ref: crate::tables::TypeRefRow =
                    row_at(&image.tables.type_refs, row, location, "attribute type")?;
                Ok(Some((
                    image.string(type_ref.namespace, location)?,
                    image.string(type_ref.name, location)?,
                )))
            }
            Some(RowRef {
                table: TableId::TypeDef,
                row,
            }) => {
                let type_def: TypeDefRow =
                    row_at(&image.tables.type_defs, row, location, "attribute type")?;
                Ok(Some((
                    image.string(type_def.namespace, location)?,
                    image.string(type_def.name, location)?,
                )))
            }
            _ => Ok(None),
        }
    }

    fn target_framework(namer: &Namer<'_, '_>) -> Outcome<(String, Option<Location>)> {
        let image: &Image<'_> = namer.image;
        let assembly: Option<RowRef> = Some(RowRef {
            table: TableId::Assembly,
            row: 1,
        });
        for (index, row) in image.tables.custom_attributes.iter().enumerate() {
            if row.parent != assembly {
                continue;
            }
            let location: Location = Location::row(TableId::CustomAttribute, rid_of(index));
            let Some((namespace, name)): Option<(String, String)> =
                Self::attribute_type_names(namer, row.attr_type, location)?
            else {
                continue;
            };
            if namespace != TARGET_FRAMEWORK.0 || name != TARGET_FRAMEWORK.1 {
                continue;
            }
            let blob: &[u8] = image.blob(row.value, location)?;
            let Some((&[0x01, 0x00], rest)): Option<(&[u8; 2], &[u8])> =
                blob.split_first_chunk::<2>()
            else {
                return Err(Fault::malformed(
                    location,
                    "attribute value lacks the 0x0001 prolog",
                ));
            };
            if rest.first() == Some(&0xFF) {
                return Ok(("null".to_owned(), Some(location)));
            }
            let (length, consumed): (u32, usize) = decompress_uint(rest).ok_or_else(|| {
                Fault::malformed(location, "attribute string length is malformed")
            })?;
            let text: &[u8] = rest
                .get(consumed..consumed.saturating_add(length as usize))
                .ok_or_else(|| {
                    Fault::malformed(location, "attribute string runs past its value")
                })?;
            return Ok((String::from_utf8_lossy(text).into_owned(), Some(location)));
        }
        Ok(("none".to_owned(), None))
    }

    fn read_assembly_refs(&mut self, namer: &mut Namer<'_, '_>) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        for (index, row) in image.tables.assembly_refs.iter().enumerate() {
            let location: Location = Location::row(TableId::AssemblyRef, rid_of(index));
            let culture: String = image.string(row.culture, location)?;
            let key: &[u8] = image.blob(row.public_key_or_token, location)?;
            let entry: Entry = Entry {
                key: image.string(row.name, location)?,
                group: String::new(),
                signature: String::new(),
                location,
                aspects: vec![
                    (
                        Aspect::Version,
                        format!("{}.{}.{}.{}", row.major, row.minor, row.build, row.revision),
                    ),
                    (
                        Aspect::Culture,
                        if culture.is_empty() {
                            "neutral".to_owned()
                        } else {
                            culture
                        },
                    ),
                    (Aspect::Flags, flags32(row.flags)),
                    (
                        Aspect::PublicKey,
                        if key.is_empty() {
                            "null".to_owned()
                        } else {
                            hex_upper(key)
                        },
                    ),
                ],
                body: None,
            };
            self.push(namer, Entity::AssemblyRef, entry)?;
        }
        Ok(())
    }

    fn read_type(
        &mut self,
        namer: &mut Namer<'_, '_>,
        rid: u32,
        property_keys: &mut BTreeMap<u32, String>,
        event_keys: &mut BTreeMap<u32, String>,
    ) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        let location: Location = Location::row(TableId::TypeDef, rid);
        let reference: RowRef = RowRef {
            table: TableId::TypeDef,
            row: rid,
        };
        let row: TypeDefRow = row_at(&image.tables.type_defs, rid, location, "type definition")?;
        let type_name: Rc<str> = namer.type_def(rid)?;
        let mut interfaces: Vec<String> = Vec::new();
        for index in rows_of(image.index.interface_impls.get(&rid)) {
            let implementation_location: Location =
                Location::row(TableId::InterfaceImpl, rid_of(*index));
            let interface: Option<RowRef> = image.tables.interface_impls[*index].interface;
            interfaces.push(
                namer
                    .optional_type(interface, implementation_location)?
                    .to_string(),
            );
        }
        let mut impls: Vec<String> = Vec::new();
        for index in rows_of(image.index.method_impls.get(&rid)) {
            let method_impl: crate::tables::MethodImplRow = image.tables.method_impls[*index];
            let impl_location: Location = Location::row(TableId::MethodImpl, rid_of(*index));
            let body: String = namer.method_ref(method_impl.method_body, impl_location)?;
            let declaration: String =
                namer.method_ref(method_impl.method_declaration, impl_location)?;
            impls.push(format!("{body} => {declaration}"));
        }
        let layout: String = image
            .index
            .class_layouts
            .get(&rid)
            .map(|index: &usize| &image.tables.class_layouts[*index])
            .map_or_else(
                || "pack 0 size 0".to_owned(),
                |layout: &crate::tables::ClassLayoutRow| {
                    format!("pack {} size {}", layout.packing_size, layout.class_size)
                },
            );
        let entry: Entry = Entry {
            key: type_name.to_string(),
            group: String::new(),
            signature: String::new(),
            location,
            aspects: vec![
                (Aspect::Flags, flags32(row.flags)),
                (
                    Aspect::Extends,
                    namer.optional_type(row.extends, location)?.to_string(),
                ),
                (Aspect::Interfaces, sorted_list(interfaces)),
                (
                    Aspect::GenericParameters,
                    Self::generic_parameters(namer, reference)?,
                ),
                (Aspect::Layout, layout),
                (Aspect::MethodImpls, sorted_list(impls)),
                (Aspect::Security, Self::security(namer, reference)?),
            ],
            body: None,
        };
        self.push(namer, Entity::Type, entry)?;
        let type_index: usize = (rid as usize).wrapping_sub(1);
        for field in rows_of(image.members.type_fields.get(type_index)) {
            self.read_field(namer, *field)?;
        }
        for method in rows_of(image.members.type_methods.get(type_index)) {
            self.read_method(namer, *method, &type_name)?;
        }
        for property in rows_of(image.members.type_properties.get(&rid)) {
            let key: String = self.read_property(namer, *property, &type_name)?;
            property_keys.insert(*property, key);
        }
        for event in rows_of(image.members.type_events.get(&rid)) {
            let key: String = self.read_event(namer, *event, &type_name)?;
            event_keys.insert(*event, key);
        }
        Ok(())
    }

    fn read_field(&mut self, namer: &mut Namer<'_, '_>, rid: u32) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        let location: Location = Location::row(TableId::Field, rid);
        let reference: RowRef = RowRef {
            table: TableId::Field,
            row: rid,
        };
        let row: crate::tables::FieldRow = row_at(&image.tables.fields, rid, location, "field")?;
        let offset: String = image.index.field_layouts.get(&rid).map_or_else(
            || "none".to_owned(),
            |index: &usize| image.extra.field_layouts[*index].0.to_string(),
        );
        let entry: Entry = Entry {
            key: namer.field_key(rid)?,
            group: String::new(),
            signature: String::new(),
            location,
            aspects: vec![
                (Aspect::Flags, flags16(row.flags)),
                (
                    Aspect::Type,
                    namer.field_blob(row.signature, location)?.to_string(),
                ),
                (Aspect::Constant, Self::constant(namer, reference)?),
                (Aspect::Offset, offset),
                (Aspect::Marshal, Self::marshal(namer, reference)?),
            ],
            body: None,
        };
        self.push(namer, Entity::Field, entry)?;
        Ok(())
    }

    fn read_method(&mut self, namer: &mut Namer<'_, '_>, rid: u32, type_name: &str) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        let location: Location = Location::row(TableId::MethodDef, rid);
        let reference: RowRef = RowRef {
            table: TableId::MethodDef,
            row: rid,
        };
        let row: crate::tables::MethodDefRow =
            row_at(&image.tables.methods, rid, location, "method")?;
        let name: String = image.string(row.name, location)?;
        let signature: SigText = namer.method_blob(row.signature, location)?;
        let mut parameters: Vec<String> = Vec::new();
        for param in rows_of(
            image
                .members
                .method_params
                .get((rid as usize).wrapping_sub(1)),
        )
        .iter()
        .copied()
        {
            let param_location: Location = Location::row(TableId::Param, param);
            let param_row: crate::tables::ParamRow =
                row_at(&image.tables.params, param, param_location, "parameter")?;
            let param_reference: RowRef = RowRef {
                table: TableId::Param,
                row: param,
            };
            let mut item: String = format!(
                "{} {} {}",
                param_row.sequence,
                image.string(param_row.name, param_location)?,
                flags16(param_row.flags)
            );
            let constant: String = Self::constant(namer, param_reference)?;
            if constant != "none" {
                let _: fmt::Result = write!(item, " = {constant}");
            }
            let marshal: String = Self::marshal(namer, param_reference)?;
            if marshal != "none" {
                let _: fmt::Result = write!(item, " marshal {marshal}");
            }
            parameters.push(item);
        }
        let il: bool = row.rva != 0 && row.impl_flags & METHOD_CODE_TYPE_MASK == 0;
        let entry: Entry = Entry {
            key: signature.member(type_name, &name),
            group: format!("{type_name}::{name}"),
            signature: signature.standalone(),
            location,
            aspects: vec![
                (Aspect::Flags, flags16(row.flags)),
                (Aspect::ImplFlags, flags16(row.impl_flags)),
                (Aspect::Parameters, format!("[{}]", parameters.join(", "))),
                (
                    Aspect::GenericParameters,
                    Self::generic_parameters(namer, reference)?,
                ),
                (Aspect::Security, Self::security(namer, reference)?),
            ],
            body: Some(BodyRef {
                rid,
                rva: il.then_some(row.rva),
            }),
        };
        self.push(namer, Entity::Method, entry)?;
        Ok(())
    }

    fn accessor_name(namer: &Namer<'_, '_>, method: u32, location: Location) -> Outcome<String> {
        let row: crate::tables::MethodDefRow = row_at(
            &namer.image.tables.methods,
            method,
            location,
            "accessor method",
        )?;
        namer
            .image
            .string(row.name, Location::row(TableId::MethodDef, method))
    }

    fn accessors(
        namer: &Namer<'_, '_>,
        association: RowRef,
        roles: &[(u16, &str)],
    ) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let mut named: Vec<Option<String>> = vec![None; roles.len()];
        let mut others: Vec<String> = Vec::new();
        for index in rows_of(image.index.semantics.get(&owner_key(association))) {
            let row: &SemanticsRow = &image.extra.semantics[*index];
            let location: Location = Location::row(TableId::MethodSemantics, rid_of(*index));
            if row.semantics == SEMANTICS_OTHER {
                others.push(format!(
                    "other {}",
                    Self::accessor_name(namer, row.method, location)?
                ));
                continue;
            }
            if let Some(slot) = roles
                .iter()
                .position(|(flag, _): &(u16, &str)| *flag == row.semantics)
            {
                named[slot] = Some(Self::accessor_name(namer, row.method, location)?);
            }
        }
        let mut parts: Vec<String> = Vec::new();
        for ((_, role), name) in roles.iter().zip(named) {
            if let Some(name) = name {
                parts.push(format!("{role} {name}"));
            }
        }
        parts.extend(others);
        Ok(format!("[{}]", parts.join(", ")))
    }

    fn read_property(
        &mut self,
        namer: &mut Namer<'_, '_>,
        rid: u32,
        type_name: &str,
    ) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let location: Location = Location::row(TableId::Property, rid);
        let reference: RowRef = RowRef {
            table: TableId::Property,
            row: rid,
        };
        let row: PropertyRow = row_at(&image.extra.properties, rid, location, "property")?;
        let name: String = image.string(row.name, location)?;
        let signature: SigText = namer.method_blob(row.signature, location)?;
        let key: String = signature.member(type_name, &name);
        let entry: Entry = Entry {
            key: key.clone(),
            group: format!("{type_name}::{name}"),
            signature: signature.standalone(),
            location,
            aspects: vec![
                (Aspect::Flags, flags16(row.flags)),
                (
                    Aspect::Accessors,
                    Self::accessors(
                        namer,
                        reference,
                        &[(SEMANTICS_GETTER, "get"), (SEMANTICS_SETTER, "set")],
                    )?,
                ),
                (Aspect::Constant, Self::constant(namer, reference)?),
            ],
            body: None,
        };
        self.push(namer, Entity::Property, entry)?;
        Ok(key)
    }

    fn read_event(
        &mut self,
        namer: &mut Namer<'_, '_>,
        rid: u32,
        type_name: &str,
    ) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let location: Location = Location::row(TableId::Event, rid);
        let reference: RowRef = RowRef {
            table: TableId::Event,
            row: rid,
        };
        let row: EventRow = row_at(&image.extra.events, rid, location, "event")?;
        let key: String = format!("{type_name}::{}", image.string(row.name, location)?);
        let entry: Entry = Entry {
            key: key.clone(),
            group: String::new(),
            signature: String::new(),
            location,
            aspects: vec![
                (Aspect::Flags, flags16(row.flags)),
                (
                    Aspect::Type,
                    namer.optional_type(row.event_type, location)?.to_string(),
                ),
                (
                    Aspect::Accessors,
                    Self::accessors(
                        namer,
                        reference,
                        &[
                            (SEMANTICS_ADD, "add"),
                            (SEMANTICS_REMOVE, "remove"),
                            (SEMANTICS_FIRE, "raise"),
                        ],
                    )?,
                ),
            ],
            body: None,
        };
        self.push(namer, Entity::Event, entry)?;
        Ok(key)
    }

    fn read_pinvokes(&mut self, namer: &mut Namer<'_, '_>) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        for (index, row) in image.tables.impl_maps.iter().enumerate() {
            let location: Location = Location::row(TableId::ImplMap, rid_of(index));
            let key: String = match row.member {
                Some(RowRef {
                    table: TableId::MethodDef,
                    row,
                }) => namer.method_key(row)?.to_string(),
                Some(RowRef {
                    table: TableId::Field,
                    row,
                }) => namer.field_key(row)?,
                _ => return Err(Fault::malformed(location, "P/Invoke names no member")),
            };
            let module: String = if row.import_scope == 0 {
                "none".to_owned()
            } else {
                namer.module_ref(row.import_scope)?
            };
            let entry: Entry = Entry {
                key,
                group: String::new(),
                signature: String::new(),
                location,
                aspects: vec![
                    (Aspect::Module, module),
                    (Aspect::EntryPoint, image.string(row.import_name, location)?),
                    (Aspect::Flags, flags16(row.flags)),
                ],
                body: None,
            };
            self.push(namer, Entity::Pinvoke, entry)?;
        }
        Ok(())
    }

    fn read_resources(&mut self, namer: &mut Namer<'_, '_>) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        for (index, row) in image.tables.manifest_resources.iter().enumerate() {
            let location: Location = Location::row(TableId::ManifestResource, rid_of(index));
            let (implementation, size, digest): (String, String, String) = match row.implementation
            {
                None => {
                    let data: &[u8] = Self::embedded_resource(image, row.offset, location)?;
                    let digest: [u8; 32] = Sha256::digest(data).into();
                    (
                        "embedded".to_owned(),
                        data.len().to_string(),
                        hex_lower(&digest),
                    )
                }
                Some(RowRef {
                    table: TableId::File,
                    row: file,
                }) => {
                    let name: u32 = row_at(&image.extra.files, file, location, "resource file")?;
                    (
                        format!(
                            "file {}",
                            image.string(name, Location::row(TableId::File, file))?
                        ),
                        "none".to_owned(),
                        "none".to_owned(),
                    )
                }
                Some(RowRef {
                    table: TableId::AssemblyRef,
                    row: assembly,
                }) => (
                    format!("assembly {}", namer.assembly_ref(assembly)?),
                    "none".to_owned(),
                    "none".to_owned(),
                ),
                Some(_) => {
                    return Err(Fault::malformed(
                        location,
                        "resource implementation names a foreign table",
                    ));
                }
            };
            let entry: Entry = Entry {
                key: image.string(row.name, location)?,
                group: String::new(),
                signature: String::new(),
                location,
                aspects: vec![
                    (Aspect::Flags, flags32(row.flags)),
                    (Aspect::Implementation, implementation),
                    (Aspect::Size, size),
                    (Aspect::Sha256, digest),
                ],
                body: None,
            };
            self.push(namer, Entity::Resource, entry)?;
        }
        Ok(())
    }

    fn embedded_resource<'a>(
        image: &Image<'a>,
        offset: u32,
        location: Location,
    ) -> Outcome<&'a [u8]> {
        let rva: u32 = image
            .clr
            .resources
            .rva
            .checked_add(offset)
            .filter(|_| image.clr.resources.rva != 0)
            .ok_or_else(|| {
                Fault::malformed(location, "embedded resource has no resources directory")
            })?;
        let header: &[u8] = image
            .pe
            .slice_at_rva(image.bytes, rva, 4)
            .map_err(|_| Fault::malformed(location, "embedded resource lies outside the image"))?;
        let length: u32 = match *header {
            [a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
            _ => {
                return Err(Fault::malformed(
                    location,
                    "embedded resource length is truncated",
                ));
            }
        };
        let start: u32 = rva
            .checked_add(4)
            .ok_or_else(|| Fault::malformed(location, "embedded resource offset overflows"))?;
        image
            .pe
            .slice_at_rva(image.bytes, start, length as usize)
            .map_err(|_| Fault::malformed(location, "embedded resource runs past the image"))
    }

    fn generic_parameter_owner(
        namer: &mut Namer<'_, '_>,
        rid: u32,
        location: Location,
    ) -> Outcome<String> {
        let row: crate::tables::GenericParamRow = row_at(
            &namer.image.tables.generic_params,
            rid,
            location,
            "generic parameter",
        )?;
        let owner: String = match row.owner {
            Some(RowRef {
                table: TableId::TypeDef,
                row,
            }) => format!("type {}", namer.type_def(row)?),
            Some(RowRef {
                table: TableId::MethodDef,
                row,
            }) => format!("method {}", namer.method_key(row)?),
            _ => return Err(Fault::malformed(location, "generic parameter has no owner")),
        };
        Ok(format!("generic-parameter {} of {owner}", row.number))
    }

    fn attribute_owner(
        namer: &mut Namer<'_, '_>,
        parent: Option<RowRef>,
        location: Location,
        property_keys: &BTreeMap<u32, String>,
        event_keys: &BTreeMap<u32, String>,
    ) -> Outcome<String> {
        let image: &Image<'_> = namer.image;
        let Some(parent): Option<RowRef> = parent else {
            return Err(Fault::malformed(location, "attribute has no parent"));
        };
        let row: u32 = parent.row;
        let missing = || Fault::malformed(location, "attribute parent does not exist");
        Ok(match parent.table {
            TableId::Assembly => "assembly".to_owned(),
            TableId::Module => "module".to_owned(),
            TableId::TypeDef => format!("type {}", namer.type_def(row)?),
            TableId::Field => format!("field {}", namer.field_key(row)?),
            TableId::MethodDef => format!("method {}", namer.method_key(row)?),
            TableId::Param => {
                let param: crate::tables::ParamRow =
                    row_at(&image.tables.params, row, location, "attribute parent")?;
                let method: u32 = image
                    .members
                    .param_owner
                    .get(&row)
                    .copied()
                    .ok_or_else(missing)?;
                format!(
                    "parameter {} of {}",
                    param.sequence,
                    namer.method_key(method)?
                )
            }
            TableId::Property => {
                format!("property {}", property_keys.get(&row).ok_or_else(missing)?)
            }
            TableId::Event => format!("event {}", event_keys.get(&row).ok_or_else(missing)?),
            TableId::InterfaceImpl => {
                let implementation: crate::tables::InterfaceImplRow = row_at(
                    &image.tables.interface_impls,
                    row,
                    location,
                    "attribute parent",
                )?;
                format!(
                    "interface {} of {}",
                    namer.optional_type(implementation.interface, location)?,
                    namer.type_def(implementation.class_type)?
                )
            }
            TableId::GenericParam => Self::generic_parameter_owner(namer, row, location)?,
            TableId::GenericParamConstraint => {
                let constraint: ConstraintRow =
                    row_at(&image.extra.constraints, row, location, "attribute parent")?;
                let reference: RowRef = constraint.constraint.ok_or_else(missing)?;
                format!(
                    "constraint {} of {}",
                    namer.type_token(reference, location)?,
                    Self::generic_parameter_owner(namer, constraint.owner, location)?
                )
            }
            TableId::TypeRef => format!("type-ref {}", namer.type_ref(row)?),
            TableId::TypeSpec => format!("type-spec {}", namer.type_spec(row)?),
            TableId::MemberRef => format!("member-ref {}", namer.member_ref(row)?.0),
            TableId::MethodSpec => format!("method-spec {}", namer.method_spec(row)?),
            TableId::StandAloneSig => format!("signature {}", namer.standalone_sig(row)?),
            TableId::ModuleRef => format!("module-ref {}", namer.module_ref(row)?),
            TableId::AssemblyRef => format!("assembly-ref {}", namer.assembly_ref(row)?),
            TableId::File => {
                let name: u32 = row_at(&image.extra.files, row, location, "attribute parent")?;
                format!("file {}", image.string(name, location)?)
            }
            TableId::ExportedType => {
                let exported: ExportedTypeRow = row_at(
                    &image.extra.exported_types,
                    row,
                    location,
                    "attribute parent",
                )?;
                format!(
                    "exported-type {}",
                    qualify(
                        &image.string(exported.namespace, location)?,
                        &image.string(exported.name, location)?
                    )
                )
            }
            TableId::ManifestResource => {
                let resource: crate::tables::ManifestResourceRow = row_at(
                    &image.tables.manifest_resources,
                    row,
                    location,
                    "attribute parent",
                )?;
                format!("resource {}", image.string(resource.name, location)?)
            }
            _ => {
                return Err(Fault::malformed(
                    location,
                    "attribute parent names a foreign table",
                ));
            }
        })
    }

    fn read_attributes(
        &mut self,
        namer: &mut Namer<'_, '_>,
        property_keys: &BTreeMap<u32, String>,
        event_keys: &BTreeMap<u32, String>,
    ) -> Outcome<()> {
        let image: &Image<'_> = namer.image;
        for (index, row) in image.tables.custom_attributes.iter().enumerate() {
            let location: Location = Location::row(TableId::CustomAttribute, rid_of(index));
            let (attribute_type, constructor): (String, SigText) = match row.attr_type {
                Some(RowRef {
                    table: TableId::MethodDef,
                    row: method,
                }) => {
                    let method_row: crate::tables::MethodDefRow = row_at(
                        &image.tables.methods,
                        method,
                        location,
                        "attribute constructor",
                    )?;
                    (
                        namer.method_owner(method)?.to_string(),
                        namer.method_blob(
                            method_row.signature,
                            Location::row(TableId::MethodDef, method),
                        )?,
                    )
                }
                Some(RowRef {
                    table: TableId::MemberRef,
                    row: member,
                }) => {
                    let member_location: Location = Location::row(TableId::MemberRef, member);
                    let member_row: crate::tables::MemberRefRow = row_at(
                        &image.tables.member_refs,
                        member,
                        location,
                        "attribute constructor",
                    )?;
                    (
                        namer.member_ref_parent(member_row.parent, member_location)?,
                        namer.method_blob(member_row.signature, member_location)?,
                    )
                }
                _ => {
                    return Err(Fault::malformed(
                        location,
                        "attribute constructor names no method",
                    ));
                }
            };
            let owner: String =
                Self::attribute_owner(namer, row.parent, location, property_keys, event_keys)?;
            let value: &[u8] = image.blob(row.value, location)?;
            let entry: AttributeEntry = AttributeEntry {
                group: format!("{owner} @ {attribute_type}"),
                value: format!("{} 0x{}", constructor.parameters(), hex_upper(value)),
                location,
            };
            namer.budget(entry.group.len().saturating_add(entry.value.len()))?;
            self.attributes.push(entry);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Bodies<'n, 'i, 'a> {
    old: &'n mut Namer<'i, 'a>,
    new: &'n mut Namer<'i, 'a>,
}

impl Bodies<'_, '_, '_> {
    fn classify(
        &mut self,
        old: BodyRef,
        new: BodyRef,
    ) -> Result<Option<(Aspect, String, String)>, CompareError> {
        let (old_rva, new_rva): (u32, u32) = match (old.rva, new.rva) {
            (None, None) => return Ok(None),
            (Some(rva), None) => {
                let body: RawBody<'_> = self
                    .old
                    .raw_body(old.rid, rva)
                    .map_err(|fault: Fault| fault.on(Side::Old))?;
                return Ok(Some((
                    Aspect::BodyIlChanged,
                    format!("{} bytes", body.body.code_size),
                    "none".to_owned(),
                )));
            }
            (None, Some(rva)) => {
                let body: RawBody<'_> = self
                    .new
                    .raw_body(new.rid, rva)
                    .map_err(|fault: Fault| fault.on(Side::New))?;
                return Ok(Some((
                    Aspect::BodyIlChanged,
                    "none".to_owned(),
                    format!("{} bytes", body.body.code_size),
                )));
            }
            (Some(old_rva), Some(new_rva)) => (old_rva, new_rva),
        };
        let old_body: RawBody<'_> = self
            .old
            .raw_body(old.rid, old_rva)
            .map_err(|fault: Fault| fault.on(Side::Old))?;
        let new_body: RawBody<'_> = self
            .new
            .raw_body(new.rid, new_rva)
            .map_err(|fault: Fault| fault.on(Side::New))?;
        let old_normal: NormalBody = self
            .old
            .normalize(old.rid, &old_body.body)
            .map_err(|fault: Fault| fault.on(Side::Old))?;
        let new_normal: NormalBody = self
            .new
            .normalize(new.rid, &new_body.body)
            .map_err(|fault: Fault| fault.on(Side::New))?;
        let raw_equal: bool = old_body.raw == new_body.raw;
        let normal_equal: bool = old_normal == new_normal;
        if raw_equal && normal_equal {
            return Ok(None);
        }
        let aspect: Aspect = if normal_equal {
            Aspect::BodyTokenRenumbered
        } else {
            Aspect::BodyIlChanged
        };
        Ok(Some((
            aspect,
            format!("{} bytes", old_body.body.code_size),
            format!("{} bytes", new_body.body.code_size),
        )))
    }
}

fn changed(
    entity: Entity,
    key: &str,
    aspect: Option<Aspect>,
    old: (&str, Option<Location>),
    new: (&str, Option<Location>),
) -> Finding {
    Finding {
        entity,
        change: Change::Changed,
        key: key.to_owned(),
        aspect,
        old: Some(old.0.to_owned()),
        new: Some(new.0.to_owned()),
        old_location: old.1,
        new_location: new.1,
    }
}

fn diff_identity(
    old: &BTreeMap<IdentityField, (String, Option<Location>)>,
    new: &BTreeMap<IdentityField, (String, Option<Location>)>,
    out: &mut Vec<Finding>,
) {
    let fields: BTreeSet<IdentityField> = old.keys().chain(new.keys()).copied().collect();
    let absent: (String, Option<Location>) = ("none".to_owned(), None);
    for field in fields {
        let before: &(String, Option<Location>) = old.get(&field).unwrap_or(&absent);
        let after: &(String, Option<Location>) = new.get(&field).unwrap_or(&absent);
        if before.0 != after.0 {
            out.push(changed(
                Entity::Identity,
                field.as_str(),
                None,
                (&before.0, before.1),
                (&after.0, after.1),
            ));
        }
    }
}

fn compare_entries(
    entity: Entity,
    old: &Entry,
    new: &Entry,
    bodies: &mut Bodies<'_, '_, '_>,
    out: &mut Vec<Finding>,
) -> Result<(), CompareError> {
    let places: (Option<Location>, Option<Location>) = (Some(old.location), Some(new.location));
    if old.signature != new.signature {
        out.push(changed(
            entity,
            &old.key,
            Some(Aspect::Signature),
            (&old.signature, places.0),
            (&new.signature, places.1),
        ));
    }
    for ((aspect, before), (_, after)) in old.aspects.iter().zip(&new.aspects) {
        if before != after {
            out.push(changed(
                entity,
                &old.key,
                Some(*aspect),
                (before, places.0),
                (after, places.1),
            ));
        }
    }
    if let (Some(old_body), Some(new_body)) = (old.body, new.body)
        && let Some((aspect, before, after)) = bodies.classify(old_body, new_body)?
    {
        out.push(changed(
            entity,
            &old.key,
            Some(aspect),
            (&before, places.0),
            (&after, places.1),
        ));
    }
    Ok(())
}

fn diff_entries(
    entity: Entity,
    olds: &[Entry],
    news: &[Entry],
    bodies: &mut Bodies<'_, '_, '_>,
    out: &mut Vec<Finding>,
) -> Result<(), CompareError> {
    let mut by_key: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (index, entry) in news.iter().enumerate() {
        by_key
            .entry(entry.key.as_str())
            .or_default()
            .push_back(index);
    }
    let mut removed: Vec<usize> = Vec::new();
    for (index, entry) in olds.iter().enumerate() {
        match by_key
            .get_mut(entry.key.as_str())
            .and_then(VecDeque::pop_front)
        {
            Some(matched) => compare_entries(entity, entry, &news[matched], bodies, out)?,
            None => removed.push(index),
        }
    }
    let mut added: BTreeSet<usize> = by_key.into_values().flatten().collect();
    let paired: bool = matches!(entity, Entity::Method | Entity::Property);
    let mut removed_set: BTreeSet<usize> = removed.iter().copied().collect();
    if paired {
        let mut old_groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for index in &removed {
            old_groups
                .entry(olds[*index].group.as_str())
                .or_default()
                .push(*index);
        }
        let mut new_groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for index in &added {
            new_groups
                .entry(news[*index].group.as_str())
                .or_default()
                .push(*index);
        }
        for (group, old_members) in &old_groups {
            if let ([old_index], Some([new_index])) = (
                old_members.as_slice(),
                new_groups.get(group).map(Vec::as_slice),
            ) {
                compare_entries(entity, &olds[*old_index], &news[*new_index], bodies, out)?;
                removed_set.remove(old_index);
                added.remove(new_index);
            }
        }
    }
    for index in removed_set {
        let entry: &Entry = &olds[index];
        out.push(Finding {
            entity,
            change: Change::Removed,
            key: entry.key.clone(),
            aspect: None,
            old: None,
            new: None,
            old_location: Some(entry.location),
            new_location: None,
        });
    }
    for index in added {
        let entry: &Entry = &news[index];
        out.push(Finding {
            entity,
            change: Change::Added,
            key: entry.key.clone(),
            aspect: None,
            old: None,
            new: None,
            old_location: None,
            new_location: Some(entry.location),
        });
    }
    Ok(())
}

fn diff_attributes(olds: &[AttributeEntry], news: &[AttributeEntry], out: &mut Vec<Finding>) {
    let mut by_value: BTreeMap<(&str, &str), VecDeque<usize>> = BTreeMap::new();
    for (index, entry) in news.iter().enumerate() {
        by_value
            .entry((entry.group.as_str(), entry.value.as_str()))
            .or_default()
            .push_back(index);
    }
    let mut removed: BTreeSet<usize> = BTreeSet::new();
    for (index, entry) in olds.iter().enumerate() {
        if by_value
            .get_mut(&(entry.group.as_str(), entry.value.as_str()))
            .and_then(VecDeque::pop_front)
            .is_none()
        {
            removed.insert(index);
        }
    }
    let mut remaining: BTreeSet<usize> = by_value.into_values().flatten().collect();
    let mut old_groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for index in &removed {
        old_groups
            .entry(olds[*index].group.as_str())
            .or_default()
            .push(*index);
    }
    let mut new_groups: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for index in &remaining {
        new_groups
            .entry(news[*index].group.as_str())
            .or_default()
            .push(*index);
    }
    for (group, old_members) in &old_groups {
        if let ([old_index], Some([new_index])) = (
            old_members.as_slice(),
            new_groups.get(group).map(Vec::as_slice),
        ) {
            let before: &AttributeEntry = &olds[*old_index];
            let after: &AttributeEntry = &news[*new_index];
            out.push(changed(
                Entity::Attribute,
                group,
                Some(Aspect::Value),
                (&before.value, Some(before.location)),
                (&after.value, Some(after.location)),
            ));
            removed.remove(old_index);
            remaining.remove(new_index);
        }
    }
    for index in removed {
        let entry: &AttributeEntry = &olds[index];
        out.push(Finding {
            entity: Entity::Attribute,
            change: Change::Removed,
            key: entry.group.clone(),
            aspect: None,
            old: Some(entry.value.clone()),
            new: None,
            old_location: Some(entry.location),
            new_location: None,
        });
    }
    for index in remaining {
        let entry: &AttributeEntry = &news[index];
        out.push(Finding {
            entity: Entity::Attribute,
            change: Change::Added,
            key: entry.group.clone(),
            aspect: None,
            old: None,
            new: Some(entry.value.clone()),
            old_location: None,
            new_location: Some(entry.location),
        });
    }
}
