use std::collections::BTreeMap;

use serde::Serialize;

use crate::error::Result;
use crate::metadata::{MetadataRoot, decompress_uint, parse_metadata_root};
use crate::model::Resolver;
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::tables::{CustomAttributeRow, ImplMapRow, RowRef, TableId, Tables};

const IMPORT_EXACT_SPELLING: u16 = 0x0001;
const IMPORT_CHAR_SET_MASK: u16 = 0x0006;
const IMPORT_BEST_FIT_MASK: u16 = 0x0030;
const IMPORT_SET_LAST_ERROR: u16 = 0x0040;
const IMPORT_CALL_CONV_MASK: u16 = 0x0700;
const IMPORT_THROW_MASK: u16 = 0x3000;
const METHOD_IMPL_PRESERVE_SIG: u16 = 0x0080;
const TYPE_INTERFACE: u32 = 0x0020;
const TYPE_IMPORT: u32 = 0x1000;
const MAX_ATTRIBUTE_ARRAY: usize = 4096;
const MAX_NAMED_ARGUMENTS: u16 = 256;
const MAX_NESTING: usize = 64;

const LIBRARY_IMPORT: (&str, &str) = ("System.Runtime.InteropServices", "LibraryImportAttribute");
const UNMANAGED_CALLERS_ONLY: (&str, &str) = (
    "System.Runtime.InteropServices",
    "UnmanagedCallersOnlyAttribute",
);
const GUID: (&str, &str) = ("System.Runtime.InteropServices", "GuidAttribute");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CharSet {
    NotSpecified,
    Ansi,
    Unicode,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallingConvention {
    NotSpecified,
    Winapi,
    Cdecl,
    Stdcall,
    Thiscall,
    Fastcall,
    Other(u16),
}

impl CharSet {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotSpecified => "charset-not-specified",
            Self::Ansi => "ansi",
            Self::Unicode => "unicode",
            Self::Auto => "auto",
        }
    }
}

impl CallingConvention {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotSpecified => "convention-not-specified",
            Self::Winapi => "winapi",
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Thiscall => "thiscall",
            Self::Fastcall => "fastcall",
            Self::Other(_) => "other-convention",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringMarshalling {
    Custom,
    Utf8,
    Utf16,
    Other(i32),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PInvoke {
    pub method: String,
    pub token: u32,
    pub module: String,
    pub entry_point: String,
    pub char_set: CharSet,
    pub calling_convention: CallingConvention,
    pub set_last_error: bool,
    pub exact_spelling: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_fit_mapping: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throw_on_unmappable_char: Option<bool>,
    pub preserve_sig: bool,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LibraryImport {
    pub method: String,
    pub token: u32,
    pub library: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_marshalling: Option<StringMarshalling>,
    pub set_last_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeCallable {
    pub method: String,
    pub token: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    pub calling_conventions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComImport {
    pub type_name: String,
    pub token: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
    pub interface: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InteropReport {
    pub pinvokes: Vec<PInvoke>,
    pub library_imports: Vec<LibraryImport>,
    pub native_callable: Vec<NativeCallable>,
    pub com_imports: Vec<ComImport>,
    pub modules: BTreeMap<String, usize>,
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Bool(bool),
    Int(i64),
    Text(Option<String>),
    List(Vec<Self>),
}

pub fn interop_report(image: &[u8]) -> Result<InteropReport> {
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?;
    Ok(interop(&resolver))
}

#[must_use]
pub fn interop(resolver: &Resolver) -> InteropReport {
    let tables: &Tables = resolver.tables();
    let names: Names = Names::build(resolver, tables);
    let mut report: InteropReport = InteropReport::default();

    for row in &tables.impl_maps {
        pinvoke(resolver, tables, &names, row, &mut report);
    }
    let mut guids: BTreeMap<u32, String> = BTreeMap::new();
    for attribute in &tables.custom_attributes {
        let (Some(parent), Some(constructor)): (Option<RowRef>, Option<RowRef>) =
            (attribute.parent, attribute.attr_type)
        else {
            continue;
        };
        let Some(owner): Option<(String, String)> = resolver.member_ref_owner(constructor) else {
            continue;
        };
        let owner: (&str, &str) = (owner.0.as_str(), owner.1.as_str());
        if owner == LIBRARY_IMPORT && parent.table == TableId::MethodDef {
            library_import(resolver, &names, attribute, parent.row, &mut report);
        } else if owner == UNMANAGED_CALLERS_ONLY && parent.table == TableId::MethodDef {
            native_callable(resolver, &names, attribute, parent.row, &mut report);
        } else if owner == GUID && parent.table == TableId::TypeDef {
            let guid: Option<String> = resolver
                .blob(attribute.value)
                .and_then(|blob: &[u8]| decode_attribute(blob, 1))
                .and_then(|(fixed, _)| match fixed.into_iter().next() {
                    Some(Value::Text(text)) => text,
                    _ => None,
                });
            if let Some(guid) = guid {
                guids.entry(parent.row).or_insert(guid);
            }
        }
    }
    for (index, row) in tables.type_defs.iter().enumerate() {
        if row.flags & TYPE_IMPORT == 0 {
            continue;
        }
        let Ok(rid): std::result::Result<u32, _> = u32::try_from(index + 1) else {
            break;
        };
        let guid: Option<String> = guids.get(&rid).cloned();
        report.com_imports.push(ComImport {
            type_name: names.type_name(rid),
            token: 0x0200_0000 | rid,
            guid,
            interface: row.flags & TYPE_INTERFACE != 0,
        });
    }
    report
}

fn pinvoke(
    resolver: &Resolver,
    tables: &Tables,
    names: &Names,
    row: &ImplMapRow,
    report: &mut InteropReport,
) {
    let Some(member): Option<RowRef> = row.member else {
        report
            .problems
            .push("an ImplMap row forwards no member".to_owned());
        return;
    };
    if member.table != TableId::MethodDef {
        report.problems.push(format!(
            "ImplMap row for {:?} {} is not a method",
            member.table, member.row
        ));
        return;
    }
    let module: String = row
        .import_scope
        .checked_sub(1)
        .and_then(|index: u32| tables.module_refs.get(index as usize))
        .map_or_else(
            || format!("<module ref {}>", row.import_scope),
            |module| resolver.string(module.name),
        );
    let impl_flags: u16 = member
        .row
        .checked_sub(1)
        .and_then(|index: u32| tables.methods.get(index as usize))
        .map_or(0, |method| method.impl_flags);
    *report.modules.entry(module.clone()).or_insert(0) += 1;
    let flags: u16 = row.flags;
    report.pinvokes.push(PInvoke {
        method: names.method_name(member.row),
        token: 0x0600_0000 | member.row,
        module,
        entry_point: resolver.string(row.import_name),
        char_set: match flags & IMPORT_CHAR_SET_MASK {
            0x0002 => CharSet::Ansi,
            0x0004 => CharSet::Unicode,
            0x0006 => CharSet::Auto,
            _ => CharSet::NotSpecified,
        },
        calling_convention: match flags & IMPORT_CALL_CONV_MASK {
            0 => CallingConvention::NotSpecified,
            0x0100 => CallingConvention::Winapi,
            0x0200 => CallingConvention::Cdecl,
            0x0300 => CallingConvention::Stdcall,
            0x0400 => CallingConvention::Thiscall,
            0x0500 => CallingConvention::Fastcall,
            other => CallingConvention::Other(other),
        },
        set_last_error: flags & IMPORT_SET_LAST_ERROR != 0,
        exact_spelling: flags & IMPORT_EXACT_SPELLING != 0,
        best_fit_mapping: match flags & IMPORT_BEST_FIT_MASK {
            0x0010 => Some(true),
            0x0020 => Some(false),
            _ => None,
        },
        throw_on_unmappable_char: match flags & IMPORT_THROW_MASK {
            0x1000 => Some(true),
            0x2000 => Some(false),
            _ => None,
        },
        preserve_sig: impl_flags & METHOD_IMPL_PRESERVE_SIG != 0,
        flags,
    });
}

fn library_import(
    resolver: &Resolver,
    names: &Names,
    attribute: &CustomAttributeRow,
    method: u32,
    report: &mut InteropReport,
) {
    let method_name: String = names.method_name(method);
    let Some((fixed, named)): Option<(Vec<Value>, BTreeMap<String, Value>)> = resolver
        .blob(attribute.value)
        .and_then(|blob: &[u8]| decode_attribute(blob, 1))
    else {
        report
            .problems
            .push(format!("LibraryImport on {method_name} does not decode"));
        return;
    };
    let library: String = match fixed.into_iter().next() {
        Some(Value::Text(Some(text))) => text,
        _ => String::new(),
    };
    report.library_imports.push(LibraryImport {
        method: method_name,
        token: 0x0600_0000 | method,
        library,
        entry_point: text(named.get("EntryPoint")),
        string_marshalling: match named.get("StringMarshalling") {
            Some(Value::Int(0)) => Some(StringMarshalling::Custom),
            Some(Value::Int(1)) => Some(StringMarshalling::Utf8),
            Some(Value::Int(2)) => Some(StringMarshalling::Utf16),
            Some(Value::Int(other)) => Some(StringMarshalling::Other(*other as i32)),
            _ => None,
        },
        set_last_error: matches!(named.get("SetLastError"), Some(Value::Bool(true))),
    });
}

fn native_callable(
    resolver: &Resolver,
    names: &Names,
    attribute: &CustomAttributeRow,
    method: u32,
    report: &mut InteropReport,
) {
    let method_name: String = names.method_name(method);
    let Some((_, named)): Option<(Vec<Value>, BTreeMap<String, Value>)> = resolver
        .blob(attribute.value)
        .and_then(|blob: &[u8]| decode_attribute(blob, 0))
    else {
        report.problems.push(format!(
            "UnmanagedCallersOnly on {method_name} does not decode"
        ));
        return;
    };
    let calling_conventions: Vec<String> = match named.get("CallConvs") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item: &Value| match item {
                Value::Text(Some(name)) => {
                    Some(name.split(',').next().unwrap_or(name).trim().to_owned())
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    report.native_callable.push(NativeCallable {
        method: method_name,
        token: 0x0600_0000 | method,
        entry_point: text(named.get("EntryPoint")),
        calling_conventions,
    });
}

fn text(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::Text(text)) => text.clone(),
        _ => None,
    }
}

struct Names {
    types: Vec<String>,
    owners: Vec<u32>,
    methods: Vec<String>,
}

impl Names {
    fn build(resolver: &Resolver, tables: &Tables) -> Self {
        let enclosing: BTreeMap<u32, u32> = tables
            .nested_classes
            .iter()
            .map(|row| (row.nested_class, row.enclosing_class))
            .collect();
        let count: usize = tables.type_defs.len();
        let mut types: Vec<String> = Vec::with_capacity(count);
        for index in 0..count {
            let mut chain: Vec<usize> = vec![index];
            let mut current: u32 = u32::try_from(index + 1).unwrap_or(u32::MAX);
            while let Some(&outer) = enclosing.get(&current) {
                if chain.len() > MAX_NESTING || outer == 0 || outer as usize > count {
                    break;
                }
                chain.push(outer as usize - 1);
                current = outer;
            }
            let outermost: &crate::tables::TypeDefRow =
                &tables.type_defs[*chain.last().unwrap_or(&index)];
            let namespace: String = resolver.string(outermost.namespace);
            let mut name: String = if namespace.is_empty() {
                String::new()
            } else {
                format!("{namespace}.")
            };
            for (position, member) in chain.iter().rev().enumerate() {
                if position > 0 {
                    name.push('/');
                }
                name.push_str(&resolver.string(tables.type_defs[*member].name));
            }
            types.push(name);
        }
        let method_count: usize = tables.methods.len();
        let mut owners: Vec<u32> = vec![0; method_count];
        let mut covered: usize = 1;
        for (index, row) in tables.type_defs.iter().enumerate() {
            let start: usize = (row.method_list as usize).max(covered);
            let end: usize = tables
                .type_defs
                .get(index + 1)
                .map_or(method_count + 1, |next| next.method_list as usize);
            let end: usize = end.min(method_count + 1);
            covered = covered.max(end);
            for rid in start..end {
                let slot: usize = tables
                    .resolve_list_rid(TableId::MethodDef, rid as u32)
                    .map_or(rid, |target: u32| target as usize);
                if let Some(owner) = owners.get_mut(slot.wrapping_sub(1)) {
                    *owner = u32::try_from(index + 1).unwrap_or(0);
                }
            }
        }
        let methods: Vec<String> = tables
            .methods
            .iter()
            .map(|row| resolver.string(row.name))
            .collect();
        Self {
            types,
            owners,
            methods,
        }
    }

    fn type_name(&self, rid: u32) -> String {
        rid.checked_sub(1)
            .and_then(|index: u32| self.types.get(index as usize))
            .cloned()
            .unwrap_or_else(|| format!("<type {rid}>"))
    }

    fn method_name(&self, rid: u32) -> String {
        let index: Option<usize> = rid.checked_sub(1).map(|index: u32| index as usize);
        let method: String = index
            .and_then(|index: usize| self.methods.get(index))
            .cloned()
            .unwrap_or_else(|| format!("<method {rid}>"));
        let owner: u32 = index
            .and_then(|index: usize| self.owners.get(index))
            .copied()
            .unwrap_or(0);
        if owner == 0 {
            method
        } else {
            format!("{}::{method}", self.type_name(owner))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Primitive(u8),
    Enum,
    Boxed,
    Array(Box<Self>),
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let end: usize = self.at.checked_add(len)?;
        let slice: &[u8] = self.data.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes: &[u8]| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes: &[u8]| u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn i32(&mut self) -> Option<i32> {
        self.take(4)
            .map(|bytes: &[u8]| i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Option<i64> {
        let bytes: &[u8] = self.take(8)?;
        let mut raw: [u8; 8] = [0; 8];
        raw.copy_from_slice(bytes);
        Some(i64::from_le_bytes(raw))
    }

    fn ser_string(&mut self) -> Option<Value> {
        if self.data.get(self.at) == Some(&0xFF) {
            self.at += 1;
            return Some(Value::Text(None));
        }
        let (length, consumed): (u32, usize) = decompress_uint(self.data.get(self.at..)?)?;
        self.at += consumed;
        let bytes: &[u8] = self.take(length as usize)?;
        Some(Value::Text(Some(
            String::from_utf8_lossy(bytes).into_owned(),
        )))
    }

    fn kind(&mut self, depth: u8) -> Option<Kind> {
        match self.u8()? {
            primitive @ (0x02..=0x0E | 0x50) => Some(Kind::Primitive(primitive)),
            0x51 => Some(Kind::Boxed),
            0x55 => {
                self.ser_string()?;
                Some(Kind::Enum)
            }
            0x1D if depth == 0 => Some(Kind::Array(Box::new(self.kind(depth + 1)?))),
            _ => None,
        }
    }

    fn value(&mut self, kind: &Kind, depth: u8) -> Option<Value> {
        match kind {
            Kind::Primitive(0x02) => Some(Value::Bool(self.u8()? != 0)),
            Kind::Primitive(0x03..=0x05) => Some(Value::Int(i64::from(self.u8()?))),
            Kind::Primitive(0x06 | 0x07) => Some(Value::Int(i64::from(self.u16()?))),
            Kind::Primitive(0x08 | 0x09) | Kind::Enum => Some(Value::Int(i64::from(self.i32()?))),
            Kind::Primitive(0x0A | 0x0B | 0x0D) => Some(Value::Int(self.i64()?)),
            Kind::Primitive(0x0C) => self.take(4).map(|_| Value::Int(0)),
            Kind::Primitive(0x0E | 0x50) => self.ser_string(),
            Kind::Boxed if depth < 2 => {
                let inner: Kind = self.kind(depth + 1)?;
                self.value(&inner, depth + 1)
            }
            Kind::Primitive(_) | Kind::Boxed => None,
            Kind::Array(element) => {
                let count: i32 = self.i32()?;
                let Ok(count): std::result::Result<usize, _> = usize::try_from(count) else {
                    return Some(Value::List(Vec::new()));
                };
                if count > MAX_ATTRIBUTE_ARRAY {
                    return None;
                }
                let mut items: Vec<Value> = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(element, depth + 1)?);
                }
                Some(Value::List(items))
            }
        }
    }
}

fn decode_attribute(
    blob: &[u8],
    fixed_strings: usize,
) -> Option<(Vec<Value>, BTreeMap<String, Value>)> {
    let mut reader: Reader<'_> = Reader { data: blob, at: 0 };
    if reader.u16()? != 0x0001 {
        return None;
    }
    let mut fixed: Vec<Value> = Vec::with_capacity(fixed_strings);
    for _ in 0..fixed_strings {
        fixed.push(reader.ser_string()?);
    }
    let count: u16 = reader.u16()?;
    if count > MAX_NAMED_ARGUMENTS {
        return None;
    }
    let mut named: BTreeMap<String, Value> = BTreeMap::new();
    for _ in 0..count {
        if !matches!(reader.u8()?, 0x53 | 0x54) {
            return None;
        }
        let kind: Kind = reader.kind(0)?;
        let Value::Text(Some(name)) = reader.ser_string()? else {
            return None;
        };
        let value: Value = reader.value(&kind, 0)?;
        named.insert(name, value);
    }
    Some((fixed, named))
}
