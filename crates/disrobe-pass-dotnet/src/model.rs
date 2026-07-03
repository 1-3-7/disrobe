use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::metadata::{MetadataRoot, decompress_uint};
use crate::pe::{ClrHeader, PeImage};
use crate::signature::{MethodSig, TypeSig, parse_field_sig, parse_method_sig};
use crate::structurize::TargetLang;
use crate::tables::{
    FieldRow, GenericParamRow, MemberRefRow, MethodDefRow, MethodSpecRow, RowRef, TableId, Tables,
    TypeDefRow, TypeRefRow, TypeSpecRow, parse_tables,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeModel {
    pub token: u32,
    pub namespace: String,
    pub name: String,
    pub full_name: String,
    pub flags: u32,
    pub base_type: Option<String>,
    pub fields: Vec<FieldModel>,
    pub methods: Vec<MethodModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldModel {
    pub token: u32,
    pub name: String,
    pub flags: u16,
    pub field_type: TypeSig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodModel {
    pub token: u32,
    pub name: String,
    pub flags: u16,
    pub impl_flags: u16,
    pub rva: u32,
    pub signature: MethodSig,
    pub parameters: Vec<ParamModel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamModel {
    pub sequence: u16,
    pub name: String,
}

const METHOD_STATIC: u16 = 0x0010;
const METHOD_ACCESS_MASK: u16 = 0x0007;

impl MethodModel {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.flags & METHOD_STATIC != 0
    }

    #[must_use]
    pub fn csharp_signature(&self) -> String {
        self.signature_in(TargetLang::CSharp)
    }

    #[must_use]
    pub fn fsharp_signature(&self) -> String {
        self.signature_in(TargetLang::FSharp)
    }

    #[must_use]
    pub fn vbnet_signature(&self) -> String {
        self.signature_in(TargetLang::VbNet)
    }

    fn display_name(&self) -> String {
        self.name
            .rsplit("::")
            .next()
            .unwrap_or(&self.name)
            .to_owned()
    }

    #[must_use]
    pub fn param_name(&self, index: usize) -> String {
        self.parameters
            .iter()
            .find(|pm: &&ParamModel| usize::from(pm.sequence) == index + 1)
            .map_or_else(
                || format!("arg{}", index + 1),
                |pm: &ParamModel| pm.name.clone(),
            )
    }

    #[must_use]
    pub fn param_names(&self) -> Vec<String> {
        (0..self.signature.params.len())
            .map(|i: usize| self.param_name(i))
            .collect()
    }

    fn signature_in(&self, lang: TargetLang) -> String {
        match lang {
            TargetLang::CSharp => self.csharp_header(),
            TargetLang::FSharp => self.fsharp_header(),
            TargetLang::VbNet => self.vbnet_header(),
        }
    }

    fn csharp_header(&self) -> String {
        let vis: &str = match self.flags & METHOD_ACCESS_MASK {
            0x0001 => "private ",
            0x0002 | 0x0003 => "private protected ",
            0x0004 => "internal ",
            0x0005 => "protected ",
            0x0006 => "protected internal ",
            0x0007 => "public ",
            _ => "",
        };
        let stat: &str = if self.is_static() { "static " } else { "" };
        let ret: String = self.signature.return_type.render_in(TargetLang::CSharp);
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{} {}",
                p.render_in(TargetLang::CSharp),
                self.param_name(i)
            ));
        }
        format!("{vis}{stat}{ret} {display_name}({})", rendered.join(", "))
    }

    fn fsharp_header(&self) -> String {
        let member: &str = if self.is_static() {
            "static member"
        } else {
            "member"
        };
        let ret: String = self.signature.return_type.render_in(TargetLang::FSharp);
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{}: {}",
                self.param_name(i),
                p.render_in(TargetLang::FSharp)
            ));
        }
        format!("{member} {display_name}({}) : {ret}", rendered.join(", "))
    }

    fn vbnet_header(&self) -> String {
        let vis: &str = match self.flags & METHOD_ACCESS_MASK {
            0x0001 => "Private ",
            0x0002 | 0x0003 => "Private Protected ",
            0x0004 => "Friend ",
            0x0005 => "Protected ",
            0x0006 => "Protected Friend ",
            0x0007 => "Public ",
            _ => "",
        };
        let shared: &str = if self.is_static() { "Shared " } else { "" };
        let returns_value: bool = !matches!(
            self.signature.return_type,
            crate::signature::TypeSigOrVoid::Void
        );
        let keyword: &str = if returns_value { "Function" } else { "Sub" };
        let display_name: String = self.display_name();
        let mut rendered: Vec<String> = Vec::with_capacity(self.signature.params.len());
        for (i, p) in self.signature.params.iter().enumerate() {
            rendered.push(format!(
                "{} As {}",
                self.param_name(i),
                p.render_in(TargetLang::VbNet)
            ));
        }
        let head: String = format!(
            "{vis}{shared}{keyword} {display_name}({})",
            rendered.join(", ")
        );
        if returns_value {
            format!(
                "{head} As {}",
                self.signature.return_type.render_in(TargetLang::VbNet)
            )
        } else {
            head
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssemblyModel {
    pub module_name: String,
    pub assembly_name: Option<String>,
    pub types: Vec<TypeModel>,
    pub method_count: u32,
    pub field_count: u32,
    pub type_count: u32,
}

#[derive(Debug)]
pub struct Resolver {
    tables: Tables,
    strings_heap: Vec<u8>,
    blob: Vec<u8>,
    us: Vec<u8>,
}

impl Resolver {
    pub fn build(image: &[u8], pe: &PeImage, clr: &ClrHeader, root: &MetadataRoot) -> Result<Self> {
        let metadata_slice: &[u8] =
            pe.slice_at_rva(image, clr.metadata.rva, clr.metadata.size as usize)?;
        let table_header: crate::metadata::StreamHeader = root
            .streams
            .get("#~")
            .or_else(|| root.streams.get("#-"))
            .copied()
            .ok_or_else(|| Error::UnknownStream("#~".to_owned()))?;
        let tables: Tables = parse_tables(metadata_slice, table_header)?;
        let strings_heap: Vec<u8> = root
            .streams
            .get("#Strings")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        let blob: Vec<u8> = root
            .streams
            .get("#Blob")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        let us: Vec<u8> = root
            .streams
            .get("#US")
            .map(|h| {
                let o: usize = h.offset as usize;
                let e: usize = o.saturating_add(h.size as usize).min(metadata_slice.len());
                if o < e {
                    metadata_slice[o..e].to_vec()
                } else {
                    Vec::new()
                }
            })
            .unwrap_or_default();
        Ok(Self {
            tables,
            strings_heap,
            blob,
            us,
        })
    }

    #[must_use]
    pub const fn tables(&self) -> &Tables {
        &self.tables
    }

    #[must_use]
    pub fn type_generic_param_names(&self, type_def_rid: u32) -> Vec<String> {
        let mut named: Vec<(u16, String)> = self
            .tables
            .generic_params
            .iter()
            .filter(|g: &&GenericParamRow| {
                g.owner.is_some_and(|o: RowRef| {
                    matches!(o.table, TableId::TypeDef) && o.row == type_def_rid
                })
            })
            .map(|g: &GenericParamRow| (g.number, self.string(g.name)))
            .filter(|(_, name): &(u16, String)| !name.is_empty())
            .collect();
        named.sort_by_key(|(number, _): &(u16, String)| *number);
        named
            .into_iter()
            .map(|(_, name): (u16, String)| name)
            .collect()
    }

    #[must_use]
    fn string(&self, index: u32) -> String {
        if index == 0 {
            return String::new();
        }
        let start: usize = index as usize;
        if start >= self.strings_heap.len() {
            return String::new();
        }
        let rest: &[u8] = &self.strings_heap[start..];
        let len: usize = rest.iter().position(|&b: &u8| b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..len]).into_owned()
    }

    #[must_use]
    fn blob(&self, index: u32) -> Option<&[u8]> {
        let i: usize = index as usize;
        if i >= self.blob.len() {
            return None;
        }
        let (len, consumed): (u32, usize) = decompress_uint(&self.blob[i..])?;
        let start: usize = i + consumed;
        let end: usize = start.checked_add(len as usize)?;
        if end > self.blob.len() {
            return None;
        }
        Some(&self.blob[start..end])
    }

    #[must_use]
    pub fn user_string(&self, offset: u32) -> Option<String> {
        let i: usize = offset as usize;
        if i >= self.us.len() {
            return None;
        }
        let (len, consumed): (u32, usize) = decompress_uint(&self.us[i..])?;
        let start: usize = i + consumed;
        let blob_len: usize = len as usize;
        let end: usize = start.checked_add(blob_len)?;
        if end > self.us.len() || blob_len == 0 {
            return None;
        }
        let char_bytes: usize = blob_len - 1;
        let units: usize = char_bytes / 2;
        let mut buf: Vec<u16> = Vec::with_capacity(units);
        for u in 0..units {
            buf.push(u16::from_le_bytes([
                self.us[start + u * 2],
                self.us[start + u * 2 + 1],
            ]));
        }
        Some(String::from_utf16_lossy(&buf))
    }

    #[must_use]
    pub fn resolve_token(&self, token: u32) -> String {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let rid: u32 = token & 0x00FF_FFFF;
        if table_idx == 0x70 {
            return self
                .user_string(rid)
                .unwrap_or_else(|| format!("us(0x{rid:06X})"));
        }
        let Some(table): Option<TableId> = TableId::from_index(table_idx) else {
            return format!("token(0x{token:08X})");
        };
        match table {
            TableId::TypeDef => self
                .type_def_name(rid)
                .unwrap_or_else(|| format!("TypeDef[{rid}]")),
            TableId::TypeRef => self
                .type_ref_name(rid)
                .unwrap_or_else(|| format!("TypeRef[{rid}]")),
            TableId::MethodDef => self
                .method_name(rid)
                .unwrap_or_else(|| format!("MethodDef[{rid}]")),
            TableId::Field => self
                .field_name(rid)
                .unwrap_or_else(|| format!("Field[{rid}]")),
            TableId::MemberRef => self
                .member_ref_name(rid)
                .unwrap_or_else(|| format!("MemberRef[{rid}]")),
            TableId::TypeSpec => self
                .type_spec_name(rid)
                .unwrap_or_else(|| format!("TypeSpec[{rid}]")),
            TableId::MethodSpec => self
                .method_spec_name(rid)
                .unwrap_or_else(|| format!("MethodSpec[{rid}]")),
            _ => format!("{table:?}[{rid}]"),
        }
    }

    #[must_use]
    fn type_def_name(&self, rid: u32) -> Option<String> {
        let row: &TypeDefRow = self.tables.type_defs.get(rid.checked_sub(1)? as usize)?;
        Some(Self::qualify(
            self.string(row.namespace),
            self.string(row.name),
        ))
    }

    #[must_use]
    fn type_ref_name(&self, rid: u32) -> Option<String> {
        let row: &TypeRefRow = self.tables.type_refs.get(rid.checked_sub(1)? as usize)?;
        Some(Self::qualify(
            self.string(row.namespace),
            self.string(row.name),
        ))
    }

    #[must_use]
    fn method_name(&self, rid: u32) -> Option<String> {
        let row: &MethodDefRow = self.tables.methods.get(rid.checked_sub(1)? as usize)?;
        let owner: Option<String> = self.method_owner_name(rid);
        let m: String = self.string(row.name);
        Some(match owner {
            Some(o) => format!("{o}::{m}"),
            None => m,
        })
    }

    #[must_use]
    fn field_name(&self, rid: u32) -> Option<String> {
        let row: &FieldRow = self.tables.fields.get(rid.checked_sub(1)? as usize)?;
        Some(self.string(row.name))
    }

    #[must_use]
    fn member_ref_name(&self, rid: u32) -> Option<String> {
        let row: &MemberRefRow = self.tables.member_refs.get(rid.checked_sub(1)? as usize)?;
        let parent: Option<String> = row.parent.map(|p: RowRef| self.row_ref_name(p));
        let m: String = self.string(row.name);
        Some(match parent {
            Some(o) => format!("{o}::{m}"),
            None => m,
        })
    }

    #[must_use]
    fn method_spec_name(&self, rid: u32) -> Option<String> {
        let row: &MethodSpecRow = self.tables.method_specs.get(rid.checked_sub(1)? as usize)?;
        let method: RowRef = row.method?;
        Some(self.row_ref_name(method))
    }

    #[must_use]
    fn type_spec_name(&self, rid: u32) -> Option<String> {
        let row: &TypeSpecRow = self.tables.type_specs.get(rid.checked_sub(1)? as usize)?;
        let blob: &[u8] = self.blob(row.signature)?;
        let sig: crate::signature::TypeSig = crate::signature::parse_type_spec_sig(blob).ok()?;
        Some(self.substitute_type_tokens(&sig.render()))
    }

    #[must_use]
    pub fn resolve_type_tokens(&self, rendered: &str) -> String {
        self.substitute_type_tokens(rendered)
    }

    #[must_use]
    fn substitute_type_tokens(&self, rendered: &str) -> String {
        let mut out: String = String::with_capacity(rendered.len());
        let mut rest: &str = rendered;
        while let Some(pos) = rest.find("type(0x") {
            out.push_str(&rest[..pos]);
            let after: &str = &rest[pos + "type(0x".len()..];
            if let Some(end) = after.find(')')
                && end == 8
                && let Ok(token) = u32::from_str_radix(&after[..8], 16)
            {
                out.push_str(&self.resolve_token(token));
                rest = &after[end + 1..];
            } else {
                out.push_str("type(0x");
                rest = after;
            }
        }
        out.push_str(rest);
        out
    }

    #[must_use]
    fn row_ref_name(&self, r: RowRef) -> String {
        let token: u32 = (u32::from(r.table.index()) << 24) | r.row;
        self.resolve_token(token)
    }

    #[must_use]
    fn method_owner_name(&self, method_rid: u32) -> Option<String> {
        let types: &[crate::tables::TypeDefRow] = &self.tables.type_defs;
        for (idx, t) in types.iter().enumerate() {
            let start: u32 = t.method_list;
            let next: u32 = types
                .get(idx + 1)
                .map_or(self.tables.methods.len() as u32 + 1, |n| n.method_list);
            if method_rid >= start && method_rid < next {
                return Some(Self::qualify(self.string(t.namespace), self.string(t.name)));
            }
        }
        None
    }

    #[must_use]
    fn qualify(ns: String, name: String) -> String {
        let name: String = strip_generic_arity(&name);
        if ns.is_empty() {
            name
        } else {
            format!("{ns}.{name}")
        }
    }

    #[must_use]
    pub fn model(&self) -> AssemblyModel {
        let module_name: String = self
            .tables
            .modules
            .first()
            .map(|m| self.string(m.name))
            .unwrap_or_default();
        let assembly_name: Option<String> = self
            .tables
            .assembly
            .map(|a| self.string(a.name))
            .filter(|s: &String| !s.is_empty());

        let type_count: u32 = self.tables.type_defs.len() as u32;
        let field_total: u32 = self.tables.fields.len() as u32;
        let method_total: u32 = self.tables.methods.len() as u32;

        let mut types: Vec<TypeModel> = Vec::with_capacity(self.tables.type_defs.len());
        let n_types: usize = self.tables.type_defs.len();
        for (idx, t) in self.tables.type_defs.iter().enumerate() {
            let type_rid: u32 = idx as u32 + 1;
            let field_start: u32 = t.field_list;
            let field_end: u32 = self
                .tables
                .type_defs
                .get(idx + 1)
                .map_or(field_total + 1, |n| n.field_list);
            let method_start: u32 = t.method_list;
            let method_end: u32 = self
                .tables
                .type_defs
                .get(idx + 1)
                .map_or(method_total + 1, |n| n.method_list);

            let fields: Vec<FieldModel> =
                self.materialize_fields(field_start, field_end, field_total);
            let methods: Vec<MethodModel> =
                self.materialize_methods(method_start, method_end, method_total);

            let namespace: String = self.string(t.namespace);
            let name: String = self.string(t.name);
            let full_name: String = Self::qualify(namespace.clone(), name.clone());
            let base_type: Option<String> = t.extends.map(|e: RowRef| self.row_ref_name(e));
            types.push(TypeModel {
                token: (u32::from(TableId::TypeDef.index()) << 24) | type_rid,
                namespace,
                name,
                full_name,
                flags: t.flags,
                base_type,
                fields,
                methods,
            });
            let _ = n_types;
        }

        AssemblyModel {
            module_name,
            assembly_name,
            types,
            method_count: method_total,
            field_count: field_total,
            type_count,
        }
    }

    fn materialize_fields(&self, start: u32, end: u32, total: u32) -> Vec<FieldModel> {
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<FieldModel> = Vec::with_capacity((hi - lo) as usize);
        for rid in lo..hi {
            let Some(row) = self.tables.fields.get((rid - 1) as usize) else {
                break;
            };
            let field_type: TypeSig = self
                .blob(row.signature)
                .and_then(|b: &[u8]| parse_field_sig(b).ok())
                .unwrap_or(TypeSig::Unknown);
            out.push(FieldModel {
                token: (u32::from(TableId::Field.index()) << 24) | rid,
                name: self.string(row.name),
                flags: row.flags,
                field_type,
            });
        }
        out
    }

    fn materialize_methods(&self, start: u32, end: u32, total: u32) -> Vec<MethodModel> {
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<MethodModel> = Vec::with_capacity((hi - lo) as usize);
        for rid in lo..hi {
            let Some(row): Option<&MethodDefRow> = self.tables.methods.get((rid - 1) as usize)
            else {
                break;
            };
            let signature: MethodSig = self
                .blob(row.signature)
                .and_then(|b: &[u8]| parse_method_sig(b).ok())
                .unwrap_or_default();
            let parameters: Vec<ParamModel> = self.materialize_params(rid);
            out.push(MethodModel {
                token: (u32::from(TableId::MethodDef.index()) << 24) | rid,
                name: self.string(row.name),
                flags: row.flags,
                impl_flags: row.impl_flags,
                rva: row.rva,
                signature,
                parameters,
            });
        }
        out
    }

    fn materialize_params(&self, method_rid: u32) -> Vec<ParamModel> {
        let methods: &[MethodDefRow] = &self.tables.methods;
        let Some(row): Option<&MethodDefRow> = methods.get((method_rid - 1) as usize) else {
            return Vec::new();
        };
        let start: u32 = row.param_list;
        let total: u32 = self.tables.params.len() as u32;
        let end: u32 = methods
            .get(method_rid as usize)
            .map_or(total + 1, |n: &MethodDefRow| n.param_list);
        let lo: u32 = start.clamp(1, total.saturating_add(1));
        let hi: u32 = end.clamp(lo, total.saturating_add(1));
        let mut out: Vec<ParamModel> = Vec::new();
        for rid in lo..hi {
            let Some(p) = self.tables.params.get((rid - 1) as usize) else {
                break;
            };
            out.push(ParamModel {
                sequence: p.sequence,
                name: self.string(p.name),
            });
        }
        out
    }

    #[must_use]
    pub fn render_type(&self, sig: &TypeSig, lang: TargetLang) -> String {
        self.substitute_type_tokens(&sig.render_in(lang))
    }

    #[must_use]
    pub fn local_types(&self, local_var_sig_tok: u32, lang: TargetLang) -> Vec<String> {
        if local_var_sig_tok == 0 {
            return Vec::new();
        }
        let table_idx: u8 = u8::try_from(local_var_sig_tok >> 24).unwrap_or(0xFF);
        if TableId::from_index(table_idx) != Some(TableId::StandAloneSig) {
            return Vec::new();
        }
        let Some(rid): Option<usize> = (local_var_sig_tok & 0x00FF_FFFF)
            .checked_sub(1)
            .map(|r: u32| r as usize)
        else {
            return Vec::new();
        };
        let Some(row): Option<&crate::tables::StandAloneSigRow> =
            self.tables.standalone_sigs.get(rid)
        else {
            return Vec::new();
        };
        let Some(blob): Option<&[u8]> = self.blob(row.signature) else {
            return Vec::new();
        };
        crate::signature::parse_local_sig(blob).map_or_else(
            |_| Vec::new(),
            |locals: Vec<TypeSig>| {
                locals
                    .iter()
                    .map(|t: &TypeSig| self.render_type(t, lang))
                    .collect()
            },
        )
    }

    #[must_use]
    pub fn callee_signature(&self, token: u32) -> Option<MethodSig> {
        let table_idx: u8 = u8::try_from(token >> 24).unwrap_or(0xFF);
        let rid: usize = (token & 0x00FF_FFFF).checked_sub(1)? as usize;
        let blob_index: u32 = match TableId::from_index(table_idx)? {
            TableId::MethodDef => self.tables.methods.get(rid)?.signature,
            TableId::MemberRef => self.tables.member_refs.get(rid)?.signature,
            TableId::MethodSpec => {
                let method: RowRef = self.tables.method_specs.get(rid)?.method?;
                return self.callee_signature(row_ref_token(method));
            }
            _ => return None,
        };
        let blob: &[u8] = self.blob(blob_index)?;
        parse_method_sig(blob).ok()
    }

    #[must_use]
    pub fn enum_param_type_name(&self, token: u32, param_index: usize) -> Option<String> {
        let sig: MethodSig = self.callee_signature(token)?;
        let param: &TypeSig = sig.params.get(param_index)?;
        match param {
            TypeSig::NamedType {
                is_value_type: true,
                ..
            } => {
                let rendered: String = self.render_type(param, TargetLang::CSharp);
                (!rendered.is_empty()
                    && !rendered.contains('<')
                    && !rendered.contains('[')
                    && !rendered.contains('!'))
                .then_some(rendered)
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn methods_with_bodies(&self) -> Vec<(u32, String, u32)> {
        let mut out: Vec<(u32, String, u32)> = Vec::new();
        for (idx, m) in self.tables.methods.iter().enumerate() {
            if m.rva != 0 {
                let rid: u32 = idx as u32 + 1;
                let name: String = self.method_name(rid).unwrap_or_else(|| self.string(m.name));
                out.push((rid, name, m.rva));
            }
        }
        out
    }
}

#[must_use]
fn row_ref_token(r: RowRef) -> u32 {
    (u32::from(r.table as u8) << 24) | (r.row & 0x00FF_FFFF)
}

#[must_use]
fn strip_generic_arity(name: &str) -> String {
    match name.split_once('`') {
        Some((base, rest)) if rest.bytes().all(|b: u8| b.is_ascii_digit()) => base.to_owned(),
        _ => name.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::pe::{parse, parse_clr_header};

    fn load(rel: &str) -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(rel);
        std::fs::read(&path).expect("fixture")
    }

    fn resolver_for(rel: &str) -> Resolver {
        let bytes: Vec<u8> = load(rel);
        let pe: PeImage = parse(&bytes).expect("pe");
        let clr: ClrHeader = parse_clr_header(&bytes, &pe).expect("clr");
        let root: MetadataRoot =
            crate::metadata::parse_metadata_root(&bytes, &pe, &clr).expect("root");
        Resolver::build(&bytes, &pe, &clr, &root).expect("resolver")
    }

    #[test]
    fn builds_model_from_real_helloapp() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        assert!(model.type_count >= 1, "must have at least <Module>");
        assert!(
            model.method_count >= 1,
            "HelloApp must declare at least one method"
        );
        assert!(!model.module_name.is_empty(), "module row carries a name");
    }

    #[test]
    fn generic_state_machine_type_resolves_its_declared_parameter_name() {
        let r: Resolver = resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = r.model();
        let bfs: &TypeModel = model
            .types
            .iter()
            .find(|t: &&TypeModel| t.name.starts_with("<Bfs>d__"))
            .expect("<Bfs> iterator state machine type");
        let names: Vec<String> = r.type_generic_param_names(bfs.token & 0x00FF_FFFF);
        assert_eq!(
            names,
            vec!["T".to_owned()],
            "the <Bfs> state machine carries a single declared type parameter T"
        );
    }

    #[test]
    fn non_generic_type_has_no_generic_parameters() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        let ty: &TypeModel = model
            .types
            .iter()
            .find(|t: &&TypeModel| !t.name.is_empty() && t.name != "<Module>")
            .expect("a named type");
        assert!(
            r.type_generic_param_names(ty.token & 0x00FF_FFFF)
                .is_empty(),
            "a non-generic type yields no generic parameter names"
        );
    }

    #[test]
    fn helloapp_has_program_type_with_main() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let model: AssemblyModel = r.model();
        let has_method: bool = model
            .types
            .iter()
            .flat_map(|t: &TypeModel| t.methods.iter())
            .any(|m: &MethodModel| !m.name.is_empty());
        assert!(has_method, "at least one named method resolved");
    }

    #[test]
    fn methodspec_callee_signature_resolves_through_to_the_parent_method() {
        let r: Resolver = resolver_for("../../corpus/dotnet/constructs/Constructs.dll");
        let spec_count: usize = r.tables.method_specs.len();
        assert!(
            spec_count > 0,
            "Constructs uses generic LINQ (Enumerable.Select/Sum), so it must carry MethodSpec rows"
        );
        let mut resolved_with_params: usize = 0;
        for rid in 1..=spec_count {
            let table_idx: u32 = u32::from(TableId::MethodSpec as u8);
            let token: u32 = (table_idx << 24) | u32::try_from(rid).unwrap_or(0);
            if let Some(sig) = r.callee_signature(token) {
                let argc: usize = sig.params.len() + usize::from(sig.has_this);
                if argc > 0 {
                    resolved_with_params += 1;
                }
            }
        }
        assert!(
            resolved_with_params > 0,
            "at least one generic-method call must resolve a non-zero argument count through its MethodSpec parent (Select takes the source + a selector)"
        );
    }

    #[test]
    fn methods_with_bodies_have_rvas() {
        let r: Resolver = resolver_for("../../corpus/dotnet/HelloApp.dll");
        let bodies: Vec<(u32, String, u32)> = r.methods_with_bodies();
        assert!(!bodies.is_empty(), "HelloApp has methods with CIL bodies");
        for (_, _, rva) in &bodies {
            assert_ne!(*rva, 0);
        }
    }

    #[test]
    fn token_resolution_yields_names_on_megafile() {
        let r: Resolver = resolver_for("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
        let model: AssemblyModel = r.model();
        assert!(
            model.type_count > 10,
            "EdgeCases megafile declares many types; got {}",
            model.type_count
        );
        let named_types: usize = model
            .types
            .iter()
            .filter(|t: &&TypeModel| !t.name.is_empty())
            .count();
        assert!(named_types > 5, "most types resolve a name");
    }
}
