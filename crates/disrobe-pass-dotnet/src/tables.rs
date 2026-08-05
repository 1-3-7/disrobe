use std::collections::BTreeMap;

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::metadata::{StreamHeader, TableStream};

const MAX_TABLE_ROWS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TableId {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldPtr = 0x03,
    Field = 0x04,
    MethodPtr = 0x05,
    MethodDef = 0x06,
    ParamPtr = 0x07,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    Constant = 0x0B,
    CustomAttribute = 0x0C,
    FieldMarshal = 0x0D,
    DeclSecurity = 0x0E,
    ClassLayout = 0x0F,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    EventPtr = 0x13,
    Event = 0x14,
    PropertyMap = 0x15,
    PropertyPtr = 0x16,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    ImplMap = 0x1C,
    FieldRva = 0x1D,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOs = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
}

impl TableId {
    #[must_use]
    pub const fn from_index(i: u8) -> Option<Self> {
        Some(match i {
            0x00 => Self::Module,
            0x01 => Self::TypeRef,
            0x02 => Self::TypeDef,
            0x03 => Self::FieldPtr,
            0x04 => Self::Field,
            0x05 => Self::MethodPtr,
            0x06 => Self::MethodDef,
            0x07 => Self::ParamPtr,
            0x08 => Self::Param,
            0x09 => Self::InterfaceImpl,
            0x0A => Self::MemberRef,
            0x0B => Self::Constant,
            0x0C => Self::CustomAttribute,
            0x0D => Self::FieldMarshal,
            0x0E => Self::DeclSecurity,
            0x0F => Self::ClassLayout,
            0x10 => Self::FieldLayout,
            0x11 => Self::StandAloneSig,
            0x12 => Self::EventMap,
            0x13 => Self::EventPtr,
            0x14 => Self::Event,
            0x15 => Self::PropertyMap,
            0x16 => Self::PropertyPtr,
            0x17 => Self::Property,
            0x18 => Self::MethodSemantics,
            0x19 => Self::MethodImpl,
            0x1A => Self::ModuleRef,
            0x1B => Self::TypeSpec,
            0x1C => Self::ImplMap,
            0x1D => Self::FieldRva,
            0x20 => Self::Assembly,
            0x21 => Self::AssemblyProcessor,
            0x22 => Self::AssemblyOs,
            0x23 => Self::AssemblyRef,
            0x24 => Self::AssemblyRefProcessor,
            0x25 => Self::AssemblyRefOs,
            0x26 => Self::File,
            0x27 => Self::ExportedType,
            0x28 => Self::ManifestResource,
            0x29 => Self::NestedClass,
            0x2A => Self::GenericParam,
            0x2B => Self::MethodSpec,
            0x2C => Self::GenericParamConstraint,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn index(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodedIndex {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl CodedIndex {
    #[must_use]
    const fn tables(self) -> &'static [Option<TableId>] {
        match self {
            Self::TypeDefOrRef => &[
                Some(TableId::TypeDef),
                Some(TableId::TypeRef),
                Some(TableId::TypeSpec),
            ],
            Self::HasConstant => &[
                Some(TableId::Field),
                Some(TableId::Param),
                Some(TableId::Property),
            ],
            Self::HasCustomAttribute => &[
                Some(TableId::MethodDef),
                Some(TableId::Field),
                Some(TableId::TypeRef),
                Some(TableId::TypeDef),
                Some(TableId::Param),
                Some(TableId::InterfaceImpl),
                Some(TableId::MemberRef),
                Some(TableId::Module),
                None,
                Some(TableId::Property),
                Some(TableId::Event),
                Some(TableId::StandAloneSig),
                Some(TableId::ModuleRef),
                Some(TableId::TypeSpec),
                Some(TableId::Assembly),
                Some(TableId::AssemblyRef),
                Some(TableId::File),
                Some(TableId::ExportedType),
                Some(TableId::ManifestResource),
                Some(TableId::GenericParam),
                Some(TableId::GenericParamConstraint),
                Some(TableId::MethodSpec),
            ],
            Self::HasFieldMarshal => &[Some(TableId::Field), Some(TableId::Param)],
            Self::HasDeclSecurity => &[
                Some(TableId::TypeDef),
                Some(TableId::MethodDef),
                Some(TableId::Assembly),
            ],
            Self::MemberRefParent => &[
                Some(TableId::TypeDef),
                Some(TableId::TypeRef),
                Some(TableId::ModuleRef),
                Some(TableId::MethodDef),
                Some(TableId::TypeSpec),
            ],
            Self::HasSemantics => &[Some(TableId::Event), Some(TableId::Property)],
            Self::MethodDefOrRef => &[Some(TableId::MethodDef), Some(TableId::MemberRef)],
            Self::MemberForwarded => &[Some(TableId::Field), Some(TableId::MethodDef)],
            Self::Implementation => &[
                Some(TableId::File),
                Some(TableId::AssemblyRef),
                Some(TableId::ExportedType),
            ],
            Self::CustomAttributeType => &[
                None,
                None,
                Some(TableId::MethodDef),
                Some(TableId::MemberRef),
                None,
            ],
            Self::ResolutionScope => &[
                Some(TableId::Module),
                Some(TableId::ModuleRef),
                Some(TableId::AssemblyRef),
                Some(TableId::TypeRef),
            ],
            Self::TypeOrMethodDef => &[Some(TableId::TypeDef), Some(TableId::MethodDef)],
        }
    }

    #[must_use]
    const fn tag_bits(self) -> u32 {
        let n: usize = self.tables().len();
        match n {
            0 | 1 => 0,
            2 => 1,
            3..=4 => 2,
            5..=8 => 3,
            9..=16 => 4,
            _ => 5,
        }
    }

    #[must_use]
    fn index_size(self, row_counts: &BTreeMap<u8, u32>) -> usize {
        let max_rows: u32 = self
            .tables()
            .iter()
            .filter_map(|t: &Option<TableId>| {
                t.map(|id: TableId| row_counts.get(&id.index()).copied().unwrap_or(0))
            })
            .max()
            .unwrap_or(0);
        let threshold: u32 = 1u32 << (16u32.saturating_sub(self.tag_bits()));
        if max_rows < threshold { 2 } else { 4 }
    }

    #[must_use]
    pub fn decode(self, raw: u32) -> Option<(TableId, u32)> {
        let bits: u32 = self.tag_bits();
        let mask: u32 = (1u32 << bits) - 1;
        let tag: usize = (raw & mask) as usize;
        let row: u32 = raw >> bits;
        let table: TableId = (*self.tables().get(tag)?)?;
        Some((table, row))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeapWidths {
    pub strings: usize,
    pub guid: usize,
    pub blob: usize,
}

impl HeapWidths {
    #[must_use]
    pub const fn from_flags(heap_sizes: u8) -> Self {
        Self {
            strings: if heap_sizes & 0x01 != 0 { 4 } else { 2 },
            guid: if heap_sizes & 0x02 != 0 { 4 } else { 2 },
            blob: if heap_sizes & 0x04 != 0 { 4 } else { 2 },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowRef {
    pub table: TableId,

    pub row: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tables {
    pub modules: Vec<ModuleRow>,
    pub type_refs: Vec<TypeRefRow>,
    pub type_defs: Vec<TypeDefRow>,
    pub fields: Vec<FieldRow>,
    pub constants: Vec<ConstantRow>,
    pub methods: Vec<MethodDefRow>,
    pub params: Vec<ParamRow>,
    pub interface_impls: Vec<InterfaceImplRow>,
    pub member_refs: Vec<MemberRefRow>,
    pub custom_attributes: Vec<CustomAttributeRow>,
    pub module_refs: Vec<ModuleRefRow>,
    pub type_specs: Vec<TypeSpecRow>,
    pub method_specs: Vec<MethodSpecRow>,
    pub assembly: Option<AssemblyRow>,
    pub assembly_refs: Vec<AssemblyRefRow>,
    pub standalone_sigs: Vec<StandAloneSigRow>,
    pub method_impls: Vec<MethodImplRow>,
    pub nested_classes: Vec<NestedClassRow>,
    pub generic_params: Vec<GenericParamRow>,
    pub class_layouts: Vec<ClassLayoutRow>,
    pub field_rvas: Vec<FieldRvaRow>,
    pub manifest_resources: Vec<ManifestResourceRow>,
    pub field_ptrs: Vec<u32>,
    pub method_ptrs: Vec<u32>,
    pub param_ptrs: Vec<u32>,
    pub event_ptrs: Vec<u32>,
    pub property_ptrs: Vec<u32>,
    pub row_counts: BTreeMap<u8, u32>,
}

impl Tables {
    #[must_use]
    pub fn indirection(&self, base: TableId) -> Option<&[u32]> {
        let rows: &[u32] = match base {
            TableId::Field => &self.field_ptrs,
            TableId::MethodDef => &self.method_ptrs,
            TableId::Param => &self.param_ptrs,
            TableId::Event => &self.event_ptrs,
            TableId::Property => &self.property_ptrs,
            _ => return None,
        };
        (!rows.is_empty()).then_some(rows)
    }

    #[must_use]
    pub fn resolve_list_rid(&self, base: TableId, rid: u32) -> Option<u32> {
        let Some(rows): Option<&[u32]> = self.indirection(base) else {
            return Some(rid);
        };
        let index: usize = usize::try_from(rid.checked_sub(1)?).ok()?;
        rows.get(index).copied().filter(|target: &u32| *target != 0)
    }

    #[must_use]
    pub fn list_rows(&self, base: TableId) -> u32 {
        let indirect: u32 = self
            .indirection(base)
            .map_or(0, |rows: &[u32]| rows.len() as u32);
        if indirect > 0 {
            return indirect;
        }
        self.row_counts.get(&base.index()).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRow {
    pub generation: u16,
    pub name: u32,
    pub mvid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeRefRow {
    pub resolution_scope: Option<RowRef>,
    pub name: u32,
    pub namespace: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDefRow {
    pub flags: u32,
    pub name: u32,
    pub namespace: u32,
    pub extends: Option<RowRef>,
    pub field_list: u32,
    pub method_list: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRow {
    pub flags: u16,
    pub name: u32,
    pub signature: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantRow {
    pub element_type: u8,
    pub parent: Option<RowRef>,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDefRow {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: u32,
    pub signature: u32,
    pub param_list: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamRow {
    pub flags: u16,
    pub sequence: u16,
    pub name: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceImplRow {
    pub class_type: u32,
    pub interface: Option<RowRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRefRow {
    pub parent: Option<RowRef>,
    pub name: u32,
    pub signature: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomAttributeRow {
    pub parent: Option<RowRef>,
    pub attr_type: Option<RowRef>,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRefRow {
    pub name: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSpecRow {
    pub signature: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodSpecRow {
    pub method: Option<RowRef>,
    pub instantiation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandAloneSigRow {
    pub signature: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodImplRow {
    pub class_type: u32,
    pub method_body: Option<RowRef>,
    pub method_declaration: Option<RowRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyRow {
    pub hash_alg_id: u32,
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key: u32,
    pub name: u32,
    pub culture: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyRefRow {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
    pub flags: u32,
    pub public_key_or_token: u32,
    pub name: u32,
    pub culture: u32,
    pub hash_value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedClassRow {
    pub nested_class: u32,
    pub enclosing_class: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericParamRow {
    pub number: u16,
    pub flags: u16,
    pub owner: Option<RowRef>,
    pub name: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassLayoutRow {
    pub packing_size: u16,
    pub class_size: u32,
    pub parent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRvaRow {
    pub rva: u32,
    pub field: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestResourceRow {
    pub offset: u32,
    pub flags: u32,
    pub name: u32,
    pub implementation: Option<RowRef>,
}

struct Cursor<'a> {
    reader: ByteReader<'a>,
}

impl<'a> Cursor<'a> {
    #[inline]
    fn new(bytes: &'a [u8], pos: usize) -> Result<Self> {
        let mut reader: ByteReader<'a> = ByteReader::new(bytes);
        reader.seek(pos)?;
        Ok(Self { reader })
    }

    #[inline]
    fn u8(&mut self) -> Result<u8> {
        Ok(self.reader.read_u8()?)
    }

    #[inline]
    fn u16(&mut self) -> Result<u16> {
        Ok(self.reader.read_u16_le()?)
    }

    #[inline]
    fn u32(&mut self) -> Result<u32> {
        Ok(self.reader.read_u32_le()?)
    }

    #[inline]
    fn index(&mut self, width: usize) -> Result<u32> {
        if width == 4 {
            self.u32()
        } else {
            Ok(u32::from(self.u16()?))
        }
    }
}

struct Sizing {
    heap: HeapWidths,
    row_counts: BTreeMap<u8, u32>,
}

#[must_use]
pub const fn indirection_for(base: TableId) -> Option<TableId> {
    Some(match base {
        TableId::Field => TableId::FieldPtr,
        TableId::MethodDef => TableId::MethodPtr,
        TableId::Param => TableId::ParamPtr,
        TableId::Event => TableId::EventPtr,
        TableId::Property => TableId::PropertyPtr,
        _ => return None,
    })
}

impl Sizing {
    #[inline]
    fn table_rows(&self, id: TableId) -> u32 {
        self.row_counts.get(&id.index()).copied().unwrap_or(0)
    }

    #[inline]
    fn simple_index(&self, id: TableId) -> usize {
        if self.table_rows(id) >= (1u32 << 16) {
            4
        } else {
            2
        }
    }

    #[inline]
    fn coded_index(&self, ci: CodedIndex) -> usize {
        ci.index_size(&self.row_counts)
    }

    #[inline]
    fn list_index(&self, base: TableId) -> usize {
        self.simple_index(
            indirection_for(base)
                .filter(|id: &TableId| self.table_rows(*id) > 0)
                .unwrap_or(base),
        )
    }

    #[allow(clippy::match_same_arms)]
    fn row_width(&self, id: TableId) -> usize {
        let h: HeapWidths = self.heap;
        let s: usize = h.strings;
        let g: usize = h.guid;
        let b: usize = h.blob;
        match id {
            TableId::Module => 2 + s + 3 * g,
            TableId::TypeRef => self.coded_index(CodedIndex::ResolutionScope) + 2 * s,
            TableId::TypeDef => {
                4 + 2 * s
                    + self.coded_index(CodedIndex::TypeDefOrRef)
                    + self.list_index(TableId::Field)
                    + self.list_index(TableId::MethodDef)
            }
            TableId::Field => 2 + s + b,
            TableId::MethodDef => 4 + 2 + 2 + s + b + self.list_index(TableId::Param),
            TableId::Param => 2 + 2 + s,
            TableId::FieldPtr => self.simple_index(TableId::Field),
            TableId::MethodPtr => self.simple_index(TableId::MethodDef),
            TableId::ParamPtr => self.simple_index(TableId::Param),
            TableId::EventPtr => self.simple_index(TableId::Event),
            TableId::PropertyPtr => self.simple_index(TableId::Property),
            TableId::InterfaceImpl => {
                self.simple_index(TableId::TypeDef) + self.coded_index(CodedIndex::TypeDefOrRef)
            }
            TableId::MemberRef => self.coded_index(CodedIndex::MemberRefParent) + s + b,
            TableId::Constant => 1 + 1 + self.coded_index(CodedIndex::HasConstant) + b,
            TableId::CustomAttribute => {
                self.coded_index(CodedIndex::HasCustomAttribute)
                    + self.coded_index(CodedIndex::CustomAttributeType)
                    + b
            }
            TableId::FieldMarshal => self.coded_index(CodedIndex::HasFieldMarshal) + b,
            TableId::DeclSecurity => 2 + self.coded_index(CodedIndex::HasDeclSecurity) + b,
            TableId::ClassLayout => 2 + 4 + self.simple_index(TableId::TypeDef),
            TableId::FieldLayout => 4 + self.simple_index(TableId::Field),
            TableId::StandAloneSig => b,
            TableId::EventMap => {
                self.simple_index(TableId::TypeDef) + self.list_index(TableId::Event)
            }
            TableId::Event => 2 + s + self.coded_index(CodedIndex::TypeDefOrRef),
            TableId::PropertyMap => {
                self.simple_index(TableId::TypeDef) + self.list_index(TableId::Property)
            }
            TableId::Property => 2 + s + b,
            TableId::MethodSemantics => {
                2 + self.simple_index(TableId::MethodDef)
                    + self.coded_index(CodedIndex::HasSemantics)
            }
            TableId::MethodImpl => {
                self.simple_index(TableId::TypeDef)
                    + 2 * self.coded_index(CodedIndex::MethodDefOrRef)
            }
            TableId::ModuleRef => s,
            TableId::TypeSpec => b,
            TableId::ImplMap => {
                2 + self.coded_index(CodedIndex::MemberForwarded)
                    + s
                    + self.simple_index(TableId::ModuleRef)
            }
            TableId::FieldRva => 4 + self.simple_index(TableId::Field),
            TableId::Assembly => 4 + 2 * 4 + 4 + b + 2 * s,
            TableId::AssemblyProcessor => 4,
            TableId::AssemblyOs => 4 + 4 + 4,
            TableId::AssemblyRef => 2 * 4 + 4 + 2 * b + 2 * s,
            TableId::AssemblyRefProcessor => 4 + self.simple_index(TableId::AssemblyRef),
            TableId::AssemblyRefOs => 4 + 4 + 4 + self.simple_index(TableId::AssemblyRef),
            TableId::File => 4 + s + b,
            TableId::ExportedType => 4 + 4 + 2 * s + self.coded_index(CodedIndex::Implementation),
            TableId::ManifestResource => 4 + 4 + s + self.coded_index(CodedIndex::Implementation),
            TableId::NestedClass => 2 * self.simple_index(TableId::TypeDef),
            TableId::GenericParam => 2 + 2 + self.coded_index(CodedIndex::TypeOrMethodDef) + s,
            TableId::MethodSpec => self.coded_index(CodedIndex::MethodDefOrRef) + b,
            TableId::GenericParamConstraint => {
                self.simple_index(TableId::GenericParam)
                    + self.coded_index(CodedIndex::TypeDefOrRef)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSpan {
    pub offset: usize,
    pub row_width: usize,
    pub rows: u32,
}

pub fn table_spans(metadata_bytes: &[u8], header: StreamHeader) -> Result<BTreeMap<u8, TableSpan>> {
    let ts: TableStream = crate::metadata::parse_table_stream(metadata_bytes, header)?;
    let sizing: Sizing = Sizing {
        heap: HeapWidths::from_flags(ts.heap_sizes),
        row_counts: ts.row_counts.clone(),
    };
    let present: usize = ts.row_counts.keys().filter(|&&k: &&u8| k < 64).count();
    let mut offset: usize = 24 + 4 * present;
    let mut out: BTreeMap<u8, TableSpan> = BTreeMap::new();
    for index in 0u8..64u8 {
        let rows: u32 = ts.row_counts.get(&index).copied().unwrap_or(0);
        if rows == 0 {
            continue;
        }
        let Some(id): Option<TableId> = TableId::from_index(index) else {
            return Err(Error::UnknownStream(format!("table 0x{index:02X}")));
        };
        let row_width: usize = sizing.row_width(id);
        out.insert(
            index,
            TableSpan {
                offset,
                row_width,
                rows,
            },
        );
        offset = offset.saturating_add(row_width.saturating_mul(rows as usize));
    }
    Ok(out)
}

pub fn parse_tables(metadata_bytes: &[u8], header: StreamHeader) -> Result<Tables> {
    let off: usize = header.offset as usize;
    let end: usize = off.saturating_add(header.size as usize);
    if end > metadata_bytes.len() {
        return Err(Error::Truncated {
            offset: off,
            needed: header.size as usize,
            had: metadata_bytes.len().saturating_sub(off),
        });
    }
    let stream: &[u8] = &metadata_bytes[off..end];
    let ts: TableStream = crate::metadata::parse_table_stream(metadata_bytes, header)?;
    let total_rows: u64 = ts
        .row_counts
        .values()
        .try_fold(0u64, |total: u64, count: &u32| {
            total.checked_add(u64::from(*count))
        })
        .ok_or(Error::TableRowCountTooLarge {
            count: u64::MAX,
            cap: MAX_TABLE_ROWS,
        })?;
    if total_rows > MAX_TABLE_ROWS {
        return Err(Error::TableRowCountTooLarge {
            count: total_rows,
            cap: MAX_TABLE_ROWS,
        });
    }
    let sizing: Sizing = Sizing {
        heap: HeapWidths::from_flags(ts.heap_sizes),
        row_counts: ts.row_counts.clone(),
    };

    let mut tables: Tables = Tables {
        row_counts: ts.row_counts,
        ..Tables::default()
    };

    for (index, span) in table_spans(metadata_bytes, header)? {
        let Some(id): Option<TableId> = TableId::from_index(index) else {
            return Err(Error::UnknownStream(format!("table 0x{index:02X}")));
        };
        let table_bytes: usize =
            span.row_width
                .checked_mul(span.rows as usize)
                .ok_or(Error::Truncated {
                    offset: span.offset,
                    needed: usize::MAX,
                    had: stream.len(),
                })?;
        if span.offset.saturating_add(table_bytes) > stream.len() {
            return Err(Error::Truncated {
                offset: span.offset,
                needed: table_bytes,
                had: stream.len().saturating_sub(span.offset),
            });
        }
        decode_table(
            id,
            stream,
            span.offset,
            span.row_width,
            span.rows,
            &sizing,
            &mut tables,
        )?;
    }
    Ok(tables)
}

pub(crate) fn parse_single_assembly_row(
    metadata_bytes: &[u8],
    header: StreamHeader,
) -> Result<Option<AssemblyRow>> {
    let offset: usize = usize::try_from(header.offset).map_err(|_| Error::Truncated {
        offset: metadata_bytes.len(),
        needed: usize::MAX,
        had: 0,
    })?;
    let size: usize = usize::try_from(header.size).map_err(|_| Error::Truncated {
        offset,
        needed: usize::MAX,
        had: metadata_bytes.len().saturating_sub(offset),
    })?;
    let end: usize = offset.checked_add(size).ok_or_else(|| Error::Truncated {
        offset,
        needed: usize::MAX,
        had: metadata_bytes.len().saturating_sub(offset),
    })?;
    let stream: &[u8] = metadata_bytes
        .get(offset..end)
        .ok_or_else(|| Error::Truncated {
            offset,
            needed: size,
            had: metadata_bytes.len().saturating_sub(offset),
        })?;
    let table_stream: TableStream = crate::metadata::parse_table_stream(metadata_bytes, header)?;
    let sizing: Sizing = Sizing {
        heap: HeapWidths::from_flags(table_stream.heap_sizes),
        row_counts: table_stream.row_counts.clone(),
    };
    let present: usize = table_stream
        .row_counts
        .keys()
        .filter(|index: &&u8| **index < 64)
        .count();
    let row_count_bytes: usize = present.checked_mul(4).ok_or(Error::Truncated {
        offset,
        needed: usize::MAX,
        had: stream.len(),
    })?;
    let mut position: usize = 24usize
        .checked_add(row_count_bytes)
        .ok_or(Error::Truncated {
            offset,
            needed: usize::MAX,
            had: stream.len(),
        })?;
    let mut assembly: Option<AssemblyRow> = None;
    for index in 0u8..64u8 {
        let count_u32: u32 = table_stream.row_counts.get(&index).copied().unwrap_or(0);
        if count_u32 == 0 {
            continue;
        }
        let id: TableId = TableId::from_index(index)
            .ok_or_else(|| Error::UnknownStream(format!("table 0x{index:02X}")))?;
        let count: usize = usize::try_from(count_u32).map_err(|_| Error::Truncated {
            offset: position,
            needed: usize::MAX,
            had: stream.len().saturating_sub(position),
        })?;
        let width: usize = sizing.row_width(id);
        let table_bytes: usize = width.checked_mul(count).ok_or_else(|| Error::Truncated {
            offset: position,
            needed: usize::MAX,
            had: stream.len().saturating_sub(position),
        })?;
        let table_end: usize =
            position
                .checked_add(table_bytes)
                .ok_or_else(|| Error::Truncated {
                    offset: position,
                    needed: usize::MAX,
                    had: stream.len().saturating_sub(position),
                })?;
        if table_end > stream.len() {
            return Err(Error::Truncated {
                offset: position,
                needed: table_bytes,
                had: stream.len().saturating_sub(position),
            });
        }
        if id == TableId::Assembly {
            if count != 1 {
                return Ok(None);
            }
            let mut cursor: Cursor<'_> = Cursor::new(stream, position)?;
            assembly = Some(AssemblyRow {
                hash_alg_id: cursor.u32()?,
                major: cursor.u16()?,
                minor: cursor.u16()?,
                build: cursor.u16()?,
                revision: cursor.u16()?,
                flags: cursor.u32()?,
                public_key: cursor.index(sizing.heap.blob)?,
                name: cursor.index(sizing.heap.strings)?,
                culture: cursor.index(sizing.heap.strings)?,
            });
        }
        position = table_end;
    }
    Ok(assembly)
}

#[allow(clippy::too_many_lines)]
fn decode_table(
    id: TableId,
    stream: &[u8],
    base: usize,
    width: usize,
    count: u32,
    sz: &Sizing,
    out: &mut Tables,
) -> Result<()> {
    let coded = |c: &mut Cursor<'_>, ci: CodedIndex| -> Result<Option<RowRef>> {
        let raw: u32 = c.index(sz.coded_index(ci))?;
        Ok(ci.decode(raw).and_then(|(t, r): (TableId, u32)| {
            if r == 0 {
                None
            } else {
                Some(RowRef { table: t, row: r })
            }
        }))
    };
    match id {
        TableId::Module => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let generation: u16 = c.u16()?;
                let name: u32 = c.index(sz.heap.strings)?;
                let mvid: u32 = c.index(sz.heap.guid)?;
                out.modules.push(ModuleRow {
                    generation,
                    name,
                    mvid,
                });
            }
        }
        TableId::TypeRef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let resolution_scope: Option<RowRef> = coded(&mut c, CodedIndex::ResolutionScope)?;
                let name: u32 = c.index(sz.heap.strings)?;
                let namespace: u32 = c.index(sz.heap.strings)?;
                out.type_refs.push(TypeRefRow {
                    resolution_scope,
                    name,
                    namespace,
                });
            }
        }
        TableId::TypeDef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let flags: u32 = c.u32()?;
                let name: u32 = c.index(sz.heap.strings)?;
                let namespace: u32 = c.index(sz.heap.strings)?;
                let extends: Option<RowRef> = coded(&mut c, CodedIndex::TypeDefOrRef)?;
                let field_list: u32 = c.index(sz.simple_index(TableId::Field))?;
                let method_list: u32 = c.index(sz.simple_index(TableId::MethodDef))?;
                out.type_defs.push(TypeDefRow {
                    flags,
                    name,
                    namespace,
                    extends,
                    field_list,
                    method_list,
                });
            }
        }
        TableId::Field => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let flags: u16 = c.u16()?;
                let name: u32 = c.index(sz.heap.strings)?;
                let signature: u32 = c.index(sz.heap.blob)?;
                out.fields.push(FieldRow {
                    flags,
                    name,
                    signature,
                });
            }
        }
        TableId::Constant => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let element_type: u8 = c.u8()?;
                let _: u8 = c.u8()?;
                let parent: Option<RowRef> = coded(&mut c, CodedIndex::HasConstant)?;
                let value: u32 = c.index(sz.heap.blob)?;
                out.constants.push(ConstantRow {
                    element_type,
                    parent,
                    value,
                });
            }
        }
        TableId::MethodDef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let rva: u32 = c.u32()?;
                let impl_flags: u16 = c.u16()?;
                let flags: u16 = c.u16()?;
                let name: u32 = c.index(sz.heap.strings)?;
                let signature: u32 = c.index(sz.heap.blob)?;
                let param_list: u32 = c.index(sz.simple_index(TableId::Param))?;
                out.methods.push(MethodDefRow {
                    rva,
                    impl_flags,
                    flags,
                    name,
                    signature,
                    param_list,
                });
            }
        }
        TableId::Param => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let flags: u16 = c.u16()?;
                let sequence: u16 = c.u16()?;
                let name: u32 = c.index(sz.heap.strings)?;
                out.params.push(ParamRow {
                    flags,
                    sequence,
                    name,
                });
            }
        }
        TableId::FieldPtr
        | TableId::MethodPtr
        | TableId::ParamPtr
        | TableId::EventPtr
        | TableId::PropertyPtr => {
            let target: TableId = match id {
                TableId::FieldPtr => TableId::Field,
                TableId::MethodPtr => TableId::MethodDef,
                TableId::ParamPtr => TableId::Param,
                TableId::EventPtr => TableId::Event,
                _ => TableId::Property,
            };
            let index_width: usize = sz.simple_index(target);
            let rows: &mut Vec<u32> = match id {
                TableId::FieldPtr => &mut out.field_ptrs,
                TableId::MethodPtr => &mut out.method_ptrs,
                TableId::ParamPtr => &mut out.param_ptrs,
                TableId::EventPtr => &mut out.event_ptrs,
                _ => &mut out.property_ptrs,
            };
            rows.reserve(count as usize);
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                rows.push(c.index(index_width)?);
            }
        }
        TableId::InterfaceImpl => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let class_type: u32 = c.index(sz.simple_index(TableId::TypeDef))?;
                let interface: Option<RowRef> = coded(&mut c, CodedIndex::TypeDefOrRef)?;
                out.interface_impls.push(InterfaceImplRow {
                    class_type,
                    interface,
                });
            }
        }
        TableId::MemberRef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let parent: Option<RowRef> = coded(&mut c, CodedIndex::MemberRefParent)?;
                let name: u32 = c.index(sz.heap.strings)?;
                let signature: u32 = c.index(sz.heap.blob)?;
                out.member_refs.push(MemberRefRow {
                    parent,
                    name,
                    signature,
                });
            }
        }
        TableId::CustomAttribute => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let parent: Option<RowRef> = coded(&mut c, CodedIndex::HasCustomAttribute)?;
                let attr_type: Option<RowRef> = coded(&mut c, CodedIndex::CustomAttributeType)?;
                let value: u32 = c.index(sz.heap.blob)?;
                out.custom_attributes.push(CustomAttributeRow {
                    parent,
                    attr_type,
                    value,
                });
            }
        }
        TableId::ModuleRef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let name: u32 = c.index(sz.heap.strings)?;
                out.module_refs.push(ModuleRefRow { name });
            }
        }
        TableId::TypeSpec => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let signature: u32 = c.index(sz.heap.blob)?;
                out.type_specs.push(TypeSpecRow { signature });
            }
        }
        TableId::MethodSpec => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let method: Option<RowRef> = coded(&mut c, CodedIndex::MethodDefOrRef)?;
                let instantiation: u32 = c.index(sz.heap.blob)?;
                out.method_specs.push(MethodSpecRow {
                    method,
                    instantiation,
                });
            }
        }
        TableId::StandAloneSig => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let signature: u32 = c.index(sz.heap.blob)?;
                out.standalone_sigs.push(StandAloneSigRow { signature });
            }
        }
        TableId::MethodImpl => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let class_type: u32 = c.index(sz.simple_index(TableId::TypeDef))?;
                let method_body: Option<RowRef> = coded(&mut c, CodedIndex::MethodDefOrRef)?;
                let method_declaration: Option<RowRef> = coded(&mut c, CodedIndex::MethodDefOrRef)?;
                out.method_impls.push(MethodImplRow {
                    class_type,
                    method_body,
                    method_declaration,
                });
            }
        }
        TableId::Assembly => {
            let mut c: Cursor<'_> = Cursor::new(stream, base)?;
            let hash_alg_id: u32 = c.u32()?;
            let major: u16 = c.u16()?;
            let minor: u16 = c.u16()?;
            let build: u16 = c.u16()?;
            let revision: u16 = c.u16()?;
            let flags: u32 = c.u32()?;
            let public_key: u32 = c.index(sz.heap.blob)?;
            let name: u32 = c.index(sz.heap.strings)?;
            let culture: u32 = c.index(sz.heap.strings)?;
            out.assembly = Some(AssemblyRow {
                hash_alg_id,
                major,
                minor,
                build,
                revision,
                flags,
                public_key,
                name,
                culture,
            });
        }
        TableId::AssemblyRef => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let major: u16 = c.u16()?;
                let minor: u16 = c.u16()?;
                let build: u16 = c.u16()?;
                let revision: u16 = c.u16()?;
                let flags: u32 = c.u32()?;
                let public_key_or_token: u32 = c.index(sz.heap.blob)?;
                let name: u32 = c.index(sz.heap.strings)?;
                let culture: u32 = c.index(sz.heap.strings)?;
                let hash_value: u32 = c.index(sz.heap.blob)?;
                out.assembly_refs.push(AssemblyRefRow {
                    major,
                    minor,
                    build,
                    revision,
                    flags,
                    public_key_or_token,
                    name,
                    culture,
                    hash_value,
                });
            }
        }
        TableId::NestedClass => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let nested_class: u32 = c.index(sz.simple_index(TableId::TypeDef))?;
                let enclosing_class: u32 = c.index(sz.simple_index(TableId::TypeDef))?;
                out.nested_classes.push(NestedClassRow {
                    nested_class,
                    enclosing_class,
                });
            }
        }
        TableId::GenericParam => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let number: u16 = c.u16()?;
                let flags: u16 = c.u16()?;
                let owner: Option<RowRef> = coded(&mut c, CodedIndex::TypeOrMethodDef)?;
                let name: u32 = c.index(sz.heap.strings)?;
                out.generic_params.push(GenericParamRow {
                    number,
                    flags,
                    owner,
                    name,
                });
            }
        }
        TableId::ClassLayout => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let packing_size: u16 = c.u16()?;
                let class_size: u32 = c.u32()?;
                let parent: u32 = c.index(sz.simple_index(TableId::TypeDef))?;
                out.class_layouts.push(ClassLayoutRow {
                    packing_size,
                    class_size,
                    parent,
                });
            }
        }
        TableId::FieldRva => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let rva: u32 = c.u32()?;
                let field: u32 = c.index(sz.simple_index(TableId::Field))?;
                out.field_rvas.push(FieldRvaRow { rva, field });
            }
        }
        TableId::ManifestResource => {
            for k in 0..count as usize {
                let mut c: Cursor<'_> = Cursor::new(stream, base + k * width)?;
                let offset: u32 = c.u32()?;
                let flags: u32 = c.u32()?;
                let name: u32 = c.index(sz.heap.strings)?;
                let implementation: Option<RowRef> = coded(&mut c, CodedIndex::Implementation)?;
                out.manifest_resources.push(ManifestResourceRow {
                    offset,
                    flags,
                    name,
                    implementation,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn heap_widths_default_two_bytes() {
        let w: HeapWidths = HeapWidths::from_flags(0);
        assert_eq!(w.strings, 2);
        assert_eq!(w.guid, 2);
        assert_eq!(w.blob, 2);
    }

    #[test]
    fn table_rows_over_input_budget_are_rejected_before_decode() {
        const COUNT: u32 = 1_000_001;
        const MODULE_ROW_WIDTH: usize = 10;
        let header_size: usize = 28;
        let row_bytes: usize = MODULE_ROW_WIDTH * COUNT as usize;
        let mut bytes: Vec<u8> = vec![0; header_size + row_bytes];
        bytes[8] = 1;
        bytes[24..28].copy_from_slice(&COUNT.to_le_bytes());
        let header: StreamHeader = StreamHeader {
            offset: 0,
            size: u32::try_from(bytes.len()).expect("test metadata fits u32"),
        };

        assert!(parse_tables(&bytes, header).is_err());
    }

    #[test]
    fn heap_widths_wide_flags() {
        let w: HeapWidths = HeapWidths::from_flags(0x07);
        assert_eq!(w.strings, 4);
        assert_eq!(w.guid, 4);
        assert_eq!(w.blob, 4);
    }

    #[test]
    fn coded_index_typedeforref_tag_bits() {
        assert_eq!(CodedIndex::TypeDefOrRef.tag_bits(), 2);
        assert_eq!(CodedIndex::HasConstant.tag_bits(), 2);
        assert_eq!(CodedIndex::TypeOrMethodDef.tag_bits(), 1);
        assert_eq!(CodedIndex::HasCustomAttribute.tag_bits(), 5);
    }

    #[test]
    fn coded_index_decode_typedef() {
        let (t, r): (TableId, u32) = CodedIndex::TypeDefOrRef.decode(0b0100).expect("decode");
        assert_eq!(t, TableId::TypeDef);
        assert_eq!(r, 1);
    }

    #[test]
    fn coded_index_decode_typeref_tag() {
        let (t, r): (TableId, u32) = CodedIndex::TypeDefOrRef.decode(0b1001).expect("decode");
        assert_eq!(t, TableId::TypeRef);
        assert_eq!(r, 2);
    }

    #[test]
    fn table_id_roundtrip() {
        for i in 0u8..=0x2C {
            if let Some(id) = TableId::from_index(i) {
                assert_eq!(id.index(), i);
            }
        }
    }

    #[test]
    fn small_index_two_bytes_large_four() {
        let mut rc: BTreeMap<u8, u32> = BTreeMap::new();
        rc.insert(TableId::Field.index(), 10);
        let sz: Sizing = Sizing {
            heap: HeapWidths::from_flags(0),
            row_counts: rc,
        };
        assert_eq!(sz.simple_index(TableId::Field), 2);
        let mut rc2: BTreeMap<u8, u32> = BTreeMap::new();
        rc2.insert(TableId::Field.index(), 70_000);
        let sz2: Sizing = Sizing {
            heap: HeapWidths::from_flags(0),
            row_counts: rc2,
        };
        assert_eq!(sz2.simple_index(TableId::Field), 4);
    }
}
