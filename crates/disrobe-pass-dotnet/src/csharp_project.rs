use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::decompile::{Decompiled, decompile_assembly_detailed};
use crate::error::Result;
use crate::metadata::{MetadataRoot, parse_metadata_root};
use crate::model::{AssemblyModel, FieldConstant, FieldModel, MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::structurize::{StructuredMethod, TargetLang, csharp_escape_identifier};
use crate::tables::{CustomAttributeRow, InterfaceImplRow, NestedClassRow, RowRef, TableId};
use crate::unprotect::UnprotectReport;

const TYPE_VISIBILITY_MASK: u32 = 0x0000_0007;
const TYPE_INTERFACE: u32 = 0x0000_0020;
const TYPE_ABSTRACT: u32 = 0x0000_0080;
const TYPE_SEALED: u32 = 0x0000_0100;
const MODULE_HOLDER: &str = "__DisrobeModule";

const METHOD_ACCESS_MASK: u16 = 0x0007;
const METHOD_STATIC: u16 = 0x0010;
const METHOD_FINAL: u16 = 0x0020;
const METHOD_VIRTUAL: u16 = 0x0040;
const METHOD_NEW_SLOT: u16 = 0x0100;
const METHOD_ABSTRACT: u16 = 0x0400;
const METHOD_SPECIAL_NAME: u16 = 0x0800;
const METHOD_PINVOKE: u16 = 0x2000;

const FIELD_ACCESS_MASK: u16 = 0x0007;
const FIELD_STATIC: u16 = 0x0010;
const FIELD_INIT_ONLY: u16 = 0x0020;
const FIELD_LITERAL: u16 = 0x0040;

const BACKING_FIELD_SUFFIX: &str = ">k__BackingField";
const PREAMBLE: &str = "using System;\nusing System.Collections.Generic;\nusing System.Linq;\nusing System.Text;\nusing System.Threading.Tasks;\n\n";
const REFUSAL_MARKERS: [&str; 4] = [
    "disrobe:",
    "__unresolved",
    "__stack_underflow",
    "NotSupportedException(\"__",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub type_name: String,
    pub member: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CSharpProject {
    pub module_name: String,
    pub runtime: String,
    pub files: BTreeMap<String, String>,
    pub entry_point: Option<String>,
    pub refusals: Vec<Refusal>,
    pub protection: Option<UnprotectReport>,
}

impl CSharpProject {
    #[must_use]
    pub fn fully_recovered(&self) -> bool {
        self.refusals.is_empty()
            && self
                .protection
                .as_ref()
                .is_none_or(|p: &UnprotectReport| p.fully_recovered)
    }
}

pub fn emit_csharp_project(original: &[u8]) -> Result<CSharpProject> {
    let detailed: Decompiled = decompile_assembly_detailed(original, TargetLang::CSharp)?;
    let image: &[u8] = detailed.image(original);
    let pe: PeImage = parse(image)?;
    let clr: ClrHeader = parse_clr_header(image, &pe)?;
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr)?;
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root)?.with_renames(
        detailed
            .unprotected
            .as_ref()
            .map(|u: &crate::unprotect::Unprotected| u.member_renames.clone())
            .unwrap_or_default(),
        detailed
            .unprotected
            .as_ref()
            .map(|u: &crate::unprotect::Unprotected| u.type_renames.clone())
            .unwrap_or_default(),
        detailed
            .unprotected
            .as_ref()
            .map(|u: &crate::unprotect::Unprotected| u.namespace_renames.clone())
            .unwrap_or_default(),
    );
    let model: AssemblyModel = resolver.model();
    let bodies: BTreeMap<u32, &StructuredMethod> = detailed
        .assembly
        .methods
        .iter()
        .map(|m: &StructuredMethod| (m.token, m))
        .collect();
    let mut nested_of: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    let mut is_nested: BTreeSet<u32> = BTreeSet::new();
    for row in &resolver.tables().nested_classes {
        let NestedClassRow {
            nested_class,
            enclosing_class,
        } = *row;
        nested_of
            .entry(0x0200_0000 | enclosing_class)
            .or_default()
            .push(0x0200_0000 | nested_class);
        is_nested.insert(0x0200_0000 | nested_class);
    }
    let entry_token: Option<u32> =
        (clr.entry_point_token_or_rva >> 24 == 0x06).then_some(clr.entry_point_token_or_rva);
    let omitted_type = |token: u32| -> bool {
        detailed
            .unprotected
            .as_ref()
            .is_some_and(|u: &crate::unprotect::Unprotected| u.omits_type(token))
    };
    let omitted_method = |token: u32| -> bool {
        detailed
            .unprotected
            .as_ref()
            .is_some_and(|u: &crate::unprotect::Unprotected| u.omits_method(token))
    };
    let mut ctx: Context<'_> = Context {
        resolver: &resolver,
        model: &model,
        bodies: &bodies,
        nested_of: &nested_of,
        entry_token,
        refusals: Vec::new(),
        entry_point: None,
        omitted_type: &omitted_type,
        omitted_method: &omitted_method,
    };
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for ty in &model.types {
        if ty.full_name == "<Module>" {
            if let Some(out) = ctx.render_module_holder(ty) {
                files.insert(format!("{MODULE_HOLDER}.cs"), out);
            }
            continue;
        }
        if is_nested.contains(&ty.token) || !ctx.emits_type(ty) {
            continue;
        }
        let mut out: String = String::from(PREAMBLE);
        let namespace: String = namespace_identifier(&ty.namespace);
        let indent: usize = usize::from(!namespace.is_empty());
        if !namespace.is_empty() {
            let _ = writeln!(out, "namespace {namespace}\n{{");
        }
        ctx.render_type(ty, indent, &mut out);
        if !namespace.is_empty() {
            out.push_str("}\n");
        }
        let file: String = file_name(&ty.namespace, &ty.name, ty.token, &files);
        files.insert(file, out);
    }
    let Context {
        refusals,
        entry_point,
        ..
    } = ctx;
    Ok(CSharpProject {
        module_name: model.module_name,
        runtime: root.version,
        files,
        entry_point,
        refusals,
        protection: detailed
            .unprotected
            .as_ref()
            .map(|u: &crate::unprotect::Unprotected| u.report.clone()),
    })
}

const MAX_FILE_STEM: usize = 48;

fn file_name(namespace: &str, name: &str, token: u32, taken: &BTreeMap<String, String>) -> String {
    let full: String = if namespace.is_empty() {
        type_identifier(name)
    } else {
        format!(
            "{}.{}",
            namespace_identifier(namespace),
            type_identifier(name)
        )
    };
    let base: String = if full.chars().count() > MAX_FILE_STEM {
        let head: String = full.chars().take(MAX_FILE_STEM).collect();
        format!("{head}_{token:08x}")
    } else {
        full
    };
    let lower_taken: BTreeSet<String> = taken.keys().map(|k: &String| k.to_lowercase()).collect();
    let mut candidate: String = format!("{base}.cs");
    let mut suffix: usize = 2;
    while lower_taken.contains(&candidate.to_lowercase()) {
        candidate = format!("{base}_{suffix}.cs");
        suffix += 1;
    }
    candidate
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Class,
    Struct,
    Interface,
    Enum,
    Delegate,
}

struct Context<'a> {
    resolver: &'a Resolver,
    model: &'a AssemblyModel,
    bodies: &'a BTreeMap<u32, &'a StructuredMethod>,
    nested_of: &'a BTreeMap<u32, Vec<u32>>,
    entry_token: Option<u32>,
    refusals: Vec<Refusal>,
    entry_point: Option<String>,
    omitted_type: &'a dyn Fn(u32) -> bool,
    omitted_method: &'a dyn Fn(u32) -> bool,
}

#[must_use]
pub fn member_identifier(raw: &str) -> String {
    let mut out: String = String::with_capacity(raw.len());
    for (i, c) in raw.chars().enumerate() {
        let ok: bool = c == '_' || c.is_alphanumeric() && !(i == 0 && c.is_ascii_digit());
        if ok {
            out.push(c);
        } else if i == 0 && c.is_ascii_digit() {
            out.push('_');
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    csharp_escape_identifier(&out)
}

#[must_use]
pub fn type_identifier(raw: &str) -> String {
    let base: &str = raw.split('`').next().unwrap_or(raw);
    member_identifier(base)
}

fn namespace_identifier(raw: &str) -> String {
    raw.split('.')
        .filter(|part: &&str| !part.is_empty())
        .map(member_identifier)
        .collect::<Vec<String>>()
        .join(".")
}

fn indent_str(level: usize) -> String {
    "    ".repeat(level)
}

fn row_ref_token(row: RowRef) -> u32 {
    (u32::from(row.table.index()) << 24) | row.row
}

impl Context<'_> {
    fn render_module_holder(&mut self, module: &TypeModel) -> Option<String> {
        let methods: Vec<MethodModel> = module
            .methods
            .iter()
            .filter(|m: &&MethodModel| !(self.omitted_method)(m.token))
            .cloned()
            .collect();
        if methods.iter().all(|m: &MethodModel| m.name == ".cctor") {
            return None;
        }
        let fields: Vec<FieldModel> = module
            .fields
            .iter()
            .filter(|f: &&FieldModel| {
                let hidden: bool =
                    match &f.field_type {
                        crate::signature::TypeSig::NamedType { token, .. } => {
                            (self.omitted_type)(*token)
                                || self.model.types.iter().any(|t: &TypeModel| {
                                    t.token == *token && t.name.starts_with('<')
                                })
                        }
                        _ => false,
                    };
                !hidden
            })
            .cloned()
            .collect();
        let holder: TypeModel = TypeModel {
            token: module.token,
            namespace: String::new(),
            name: MODULE_HOLDER.to_owned(),
            full_name: MODULE_HOLDER.to_owned(),
            metadata_name: MODULE_HOLDER.to_owned(),
            flags: TYPE_ABSTRACT | TYPE_SEALED,
            base_type: Some("System.Object".to_owned()),
            fields,
            methods,
        };
        let mut out: String = format!(
            "global using static {MODULE_HOLDER};
{PREAMBLE}"
        );
        self.render_type(&holder, 0, &mut out);
        Some(out)
    }

    fn emits_type(&self, ty: &TypeModel) -> bool {
        if (self.omitted_type)(ty.token) {
            return false;
        }
        if ty.full_name == "<Module>" || ty.name.starts_with('<') {
            return false;
        }
        true
    }

    fn kind_of(ty: &TypeModel) -> Kind {
        if ty.flags & TYPE_INTERFACE != 0 {
            return Kind::Interface;
        }
        match ty.base_type.as_deref() {
            Some("System.Enum") => Kind::Enum,
            Some("System.ValueType") => Kind::Struct,
            Some("System.MulticastDelegate" | "System.Delegate") => Kind::Delegate,
            _ => Kind::Class,
        }
    }

    const fn visibility(ty: &TypeModel) -> &'static str {
        match ty.flags & TYPE_VISIBILITY_MASK {
            1 | 2 => "public",
            3 => "private",
            4 => "protected",
            6 => "private protected",
            7 => "protected internal",
            _ => "internal",
        }
    }

    fn generic_suffix(&self, ty: &TypeModel) -> String {
        let names: Vec<String> = self
            .resolver
            .type_generic_param_names(ty.token & 0x00FF_FFFF);
        if names.is_empty() {
            String::new()
        } else {
            format!("<{}>", names.join(", "))
        }
    }

    fn has_flags_attribute(&self, ty: &TypeModel) -> bool {
        self.resolver
            .tables()
            .custom_attributes
            .iter()
            .any(|row: &CustomAttributeRow| {
                row.parent.is_some_and(|p: RowRef| {
                    p.table == TableId::TypeDef && p.row == ty.token & 0x00FF_FFFF
                }) && row.attr_type.is_some_and(|a: RowRef| {
                    self.resolver
                        .resolve_token(row_ref_token(a))
                        .contains("System.FlagsAttribute")
                })
            })
    }

    fn interfaces_of(&self, ty: &TypeModel) -> Vec<String> {
        self.resolver
            .tables()
            .interface_impls
            .iter()
            .filter(|row: &&InterfaceImplRow| row.class_type == ty.token & 0x00FF_FFFF)
            .filter_map(|row: &InterfaceImplRow| row.interface)
            .map(|r: RowRef| {
                self.resolver
                    .resolve_type_tokens(&self.resolver.resolve_token(row_ref_token(r)))
            })
            .collect()
    }

    fn render_type(&mut self, ty: &TypeModel, level: usize, out: &mut String) {
        let kind: Kind = Self::kind_of(ty);
        let pad: String = indent_str(level);
        let name: String = format!("{}{}", type_identifier(&ty.name), self.generic_suffix(ty));
        match kind {
            Kind::Enum => self.render_enum(ty, &name, level, out),
            Kind::Delegate => self.render_delegate(ty, &name, level, out),
            Kind::Interface | Kind::Class | Kind::Struct => {
                let mut modifiers: Vec<&str> = vec![Self::visibility(ty)];
                let keyword: &str = match kind {
                    Kind::Interface => "interface",
                    Kind::Struct => "struct",
                    _ => {
                        let is_abstract: bool = ty.flags & TYPE_ABSTRACT != 0;
                        let is_sealed: bool = ty.flags & TYPE_SEALED != 0;
                        if is_abstract && is_sealed {
                            modifiers.push("static");
                        } else if is_abstract {
                            modifiers.push("abstract");
                        } else if is_sealed {
                            modifiers.push("sealed");
                        }
                        "class"
                    }
                };
                let mut bases: Vec<String> = Vec::new();
                if kind == Kind::Class
                    && let Some(base) = ty.base_type.as_deref()
                    && base != "System.Object"
                {
                    bases.push(self.resolver.resolve_type_tokens(base));
                }
                bases.extend(self.interfaces_of(ty));
                let inheritance: String = if bases.is_empty() {
                    String::new()
                } else {
                    format!(" : {}", bases.join(", "))
                };
                let _ = writeln!(
                    out,
                    "{pad}{} {keyword} {name}{inheritance}",
                    modifiers.join(" ")
                );
                let _ = writeln!(out, "{pad}{{");
                self.render_members(ty, kind, level + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
        }
    }

    fn render_enum(&self, ty: &TypeModel, name: &str, level: usize, out: &mut String) {
        let pad: String = indent_str(level);
        let underlying: String = ty
            .fields
            .iter()
            .find(|f: &&FieldModel| f.name == "value__")
            .map_or_else(
                || "int".to_owned(),
                |f: &FieldModel| self.resolver.render_type(&f.field_type, TargetLang::CSharp),
            );
        if self.has_flags_attribute(ty) {
            let _ = writeln!(out, "{pad}[System.Flags]");
        }
        let _ = writeln!(
            out,
            "{pad}{} enum {name} : {underlying}",
            Self::visibility(ty)
        );
        let _ = writeln!(out, "{pad}{{");
        for field in &ty.fields {
            if field.flags & FIELD_LITERAL == 0 {
                continue;
            }
            let value: String = field
                .constant
                .as_ref()
                .map_or_else(|| "0".to_owned(), csharp_constant);
            let _ = writeln!(
                out,
                "{pad}    {} = {value},",
                member_identifier(&field.name)
            );
        }
        let _ = writeln!(out, "{pad}}}");
    }

    fn render_delegate(&mut self, ty: &TypeModel, name: &str, level: usize, out: &mut String) {
        let pad: String = indent_str(level);
        let Some(invoke): Option<&MethodModel> = ty
            .methods
            .iter()
            .find(|m: &&MethodModel| m.name == "Invoke")
        else {
            self.refusals.push(Refusal {
                type_name: ty.full_name.clone(),
                member: "Invoke".to_owned(),
                reason: "delegate type has no Invoke method".to_owned(),
            });
            return;
        };
        let ret: String = self
            .resolver
            .resolve_type_tokens(&invoke.signature.return_type.render());
        let params: String = self.parameter_list(invoke);
        let _ = writeln!(
            out,
            "{pad}{} delegate {ret} {name}({params});",
            Self::visibility(ty)
        );
    }

    fn parameter_list(&self, m: &MethodModel) -> String {
        let names: Vec<String> = m.display_param_names(TargetLang::CSharp);
        m.signature
            .params
            .iter()
            .enumerate()
            .map(|(i, p): (usize, &crate::signature::TypeSig)| {
                let ty: String = self.resolver.render_type(p, TargetLang::CSharp);
                let name: String = names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| crate::names::positional_parameter_name(i));
                format!("{ty} {name}")
            })
            .collect::<Vec<String>>()
            .join(", ")
    }

    fn render_members(&mut self, ty: &TypeModel, kind: Kind, level: usize, out: &mut String) {
        let pad: String = indent_str(level);
        let method_names: BTreeSet<&str> = ty
            .methods
            .iter()
            .map(|m: &MethodModel| m.name.as_str())
            .collect();
        let mut consumed: BTreeSet<u32> = BTreeSet::new();
        for field in &ty.fields {
            if let Some(property) = backing_property_name(&field.name) {
                let getter: Option<&MethodModel> = ty
                    .methods
                    .iter()
                    .find(|m: &&MethodModel| m.name == format!("get_{property}"));
                let setter: Option<&MethodModel> = ty
                    .methods
                    .iter()
                    .find(|m: &&MethodModel| m.name == format!("set_{property}"));
                if let Some(getter) = getter {
                    consumed.insert(getter.token);
                    if let Some(setter) = setter {
                        consumed.insert(setter.token);
                    }
                    let modifiers: String = format!(
                        "{}{}",
                        Self::method_visibility(getter),
                        if field.flags & FIELD_STATIC != 0 {
                            " static"
                        } else {
                            ""
                        }
                    );
                    let accessors: &str = if setter.is_some() {
                        "get; set;"
                    } else {
                        "get; private set;"
                    };
                    let property_type: String = self
                        .resolver
                        .render_type(&field.field_type, TargetLang::CSharp);
                    let _ = writeln!(
                        out,
                        "{pad}{modifiers} {property_type} {} {{ {accessors} }}",
                        member_identifier(property)
                    );
                    continue;
                }
            }
            if kind != Kind::Interface {
                let _ = writeln!(out, "{pad}{}", self.field_declaration(field));
            }
        }
        let _ = method_names;
        let mut properties: BTreeMap<String, (Option<&MethodModel>, Option<&MethodModel>)> =
            BTreeMap::new();
        for m in &ty.methods {
            if consumed.contains(&m.token)
                || (self.omitted_method)(m.token)
                || crate::display_class_lowering::is_closure_helper_name(&m.name)
            {
                continue;
            }
            if m.flags & METHOD_SPECIAL_NAME != 0 {
                if let Some(property) = m.name.strip_prefix("get_") {
                    properties.entry(property.to_owned()).or_default().0 = Some(m);
                    continue;
                }
                if let Some(property) = m.name.strip_prefix("set_") {
                    properties.entry(property.to_owned()).or_default().1 = Some(m);
                    continue;
                }
                if m.name.starts_with("add_") || m.name.starts_with("remove_") {
                    self.refusals.push(Refusal {
                        type_name: ty.full_name.clone(),
                        member: m.name.clone(),
                        reason: "event accessors are not emitted".to_owned(),
                    });
                    continue;
                }
            }
            if kind == Kind::Delegate {
                continue;
            }
            self.render_method(ty, kind, m, level, out);
        }
        for (property, (getter, setter)) in properties {
            self.render_property(ty, kind, &property, getter, setter, level, out);
        }
        if let Some(children) = self.nested_of.get(&ty.token) {
            let child_types: Vec<&TypeModel> = children
                .iter()
                .filter_map(|token: &u32| {
                    self.model
                        .types
                        .iter()
                        .find(|t: &&TypeModel| t.token == *token)
                })
                .collect();
            for child in child_types {
                if self.emits_type(child) {
                    self.render_type(child, level, out);
                }
            }
        }
    }

    const fn method_visibility(m: &MethodModel) -> &'static str {
        match m.flags & METHOD_ACCESS_MASK {
            6 => "public",
            3 => "internal",
            4 => "protected",
            5 => "protected internal",
            2 => "private protected",
            _ => "private",
        }
    }

    fn method_modifiers(kind: Kind, m: &MethodModel) -> String {
        if kind == Kind::Interface {
            return String::new();
        }
        let mut parts: Vec<&str> = vec![Self::method_visibility(m)];
        if m.flags & METHOD_STATIC != 0 {
            parts.push("static");
        }
        if m.flags & METHOD_ABSTRACT != 0 {
            parts.push("abstract");
        } else if m.flags & METHOD_VIRTUAL != 0 {
            if m.flags & METHOD_NEW_SLOT != 0 {
                if m.flags & METHOD_FINAL == 0 {
                    parts.push("virtual");
                }
            } else if m.flags & METHOD_FINAL != 0 {
                parts.push("sealed override");
            } else {
                parts.push("override");
            }
        }
        parts.join(" ")
    }

    fn header_parameters(&self, m: &MethodModel) -> Option<String> {
        let structured: &StructuredMethod = self.bodies.get(&m.token)?;
        let header: &str = structured
            .body
            .lines()
            .find(|l: &&str| !l.trim_start().starts_with("//") && !l.trim().is_empty())?;
        let open: usize = header.find('(')?;
        let close: usize = header.rfind(')')?;
        (close > open).then(|| header[open + 1..close].to_owned())
    }

    fn body_block(&mut self, ty: &TypeModel, m: &MethodModel) -> Option<String> {
        let structured: &StructuredMethod = self.bodies.get(&m.token)?;
        let mut lines = structured.body.lines().peekable();
        while lines
            .peek()
            .is_some_and(|l: &&str| l.trim_start().starts_with("//"))
        {
            lines.next();
        }
        lines.next();
        let block: String = lines.collect::<Vec<&str>>().join("\n");
        for marker in REFUSAL_MARKERS {
            if let Some(line) = block.lines().find(|l: &&str| l.contains(marker)) {
                let excerpt: String = line.trim().chars().take(160).collect();
                self.refusals.push(Refusal {
                    type_name: ty.full_name.clone(),
                    member: m.name.clone(),
                    reason: format!(
                        "the decompiled body carries the refusal marker {marker:?}: {excerpt}"
                    ),
                });
                break;
            }
        }
        Some(block)
    }

    fn render_method(
        &mut self,
        ty: &TypeModel,
        kind: Kind,
        m: &MethodModel,
        level: usize,
        out: &mut String,
    ) {
        let pad: String = indent_str(level);
        let is_entry: bool = self.entry_token == Some(m.token);
        let type_name: String = type_identifier(&ty.name);
        let block: Option<String> = self.body_block(ty, m);
        let ret: String = self
            .resolver
            .resolve_type_tokens(&m.signature.return_type.render());
        let params: String = self
            .header_parameters(m)
            .unwrap_or_else(|| self.parameter_list(m));
        let generic: String = {
            let names: Vec<String> = self
                .resolver
                .method_generic_param_names(m.token & 0x00FF_FFFF);
            if names.is_empty() {
                String::new()
            } else {
                format!("<{}>", names.join(", "))
            }
        };
        let header: String = if m.name == ".ctor" {
            format!("{} {type_name}({params})", Self::method_visibility(m))
        } else if m.name == ".cctor" {
            format!("static {type_name}()")
        } else if is_entry {
            self.entry_point = Some(format!("{}.Main", ty.full_name));
            format!("{} static {ret} Main({params})", Self::method_visibility(m))
        } else if let Some(operator) = operator_symbol(&m.name) {
            format!("public static {ret} operator {operator}({params})")
        } else if m.name == "op_Implicit" || m.name == "op_Explicit" {
            let conversion: &str = if m.name == "op_Implicit" {
                "implicit"
            } else {
                "explicit"
            };
            format!("public static {conversion} operator {ret}({params})")
        } else if m.name.contains('.') {
            format!("{ret} {}{generic}({params})", m.name)
        } else {
            let modifiers: String = Self::method_modifiers(kind, m);
            let space: &str = if modifiers.is_empty() { "" } else { " " };
            format!(
                "{modifiers}{space}{ret} {}{generic}({params})",
                member_identifier(&m.name)
            )
        };
        match block {
            Some(block) if m.flags & METHOD_ABSTRACT == 0 && kind != Kind::Interface => {
                let _ = writeln!(out, "{pad}{header}");
                for line in block.lines() {
                    let _ = writeln!(out, "{pad}{line}");
                }
            }
            _ => {
                if m.flags & METHOD_ABSTRACT != 0 || kind == Kind::Interface {
                    let _ = writeln!(out, "{pad}{header};");
                } else {
                    let reason: &str = if m.flags & METHOD_PINVOKE != 0 {
                        "platform-invoke methods have no managed body to recover"
                    } else if m.rva == 0 {
                        "the method has no CIL body"
                    } else {
                        "the decompiler produced no body for this method"
                    };
                    self.refusals.push(Refusal {
                        type_name: ty.full_name.clone(),
                        member: m.name.clone(),
                        reason: reason.to_owned(),
                    });
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn render_property(
        &mut self,
        ty: &TypeModel,
        kind: Kind,
        property: &str,
        getter: Option<&MethodModel>,
        setter: Option<&MethodModel>,
        level: usize,
        out: &mut String,
    ) {
        let pad: String = indent_str(level);
        let Some(anchor): Option<&MethodModel> = getter.or(setter) else {
            return;
        };
        let property_type: String = match getter {
            Some(g) => self
                .resolver
                .resolve_type_tokens(&g.signature.return_type.render()),
            None => setter
                .and_then(|s: &MethodModel| s.signature.params.last())
                .map_or_else(
                    || "object".to_owned(),
                    |p| self.resolver.render_type(p, TargetLang::CSharp),
                ),
        };
        let modifiers: String = Self::method_modifiers(kind, anchor);
        let space: &str = if modifiers.is_empty() { "" } else { " " };
        let indexer_params: Vec<&crate::signature::TypeSig> = getter.map_or_else(
            || {
                setter.map_or_else(Vec::new, |s: &MethodModel| {
                    s.signature
                        .params
                        .iter()
                        .take(s.signature.params.len().saturating_sub(1))
                        .collect()
                })
            },
            |g: &MethodModel| g.signature.params.iter().collect(),
        );
        let declaration: String = if indexer_params.is_empty() {
            format!(
                "{modifiers}{space}{property_type} {}",
                member_identifier(property)
            )
        } else {
            let names: Vec<String> = anchor.display_param_names(TargetLang::CSharp);
            let params: String = indexer_params
                .iter()
                .enumerate()
                .map(|(i, p): (usize, &&crate::signature::TypeSig)| {
                    format!(
                        "{} {}",
                        self.resolver.render_type(p, TargetLang::CSharp),
                        names
                            .get(i)
                            .cloned()
                            .unwrap_or_else(|| crate::names::positional_parameter_name(i))
                    )
                })
                .collect::<Vec<String>>()
                .join(", ");
            format!("{modifiers}{space}{property_type} this[{params}]")
        };
        let _ = writeln!(out, "{pad}{declaration}");
        let _ = writeln!(out, "{pad}{{");
        for (accessor, method) in [("get", getter), ("set", setter)] {
            let Some(method) = method else {
                continue;
            };
            if kind == Kind::Interface || method.flags & METHOD_ABSTRACT != 0 {
                let _ = writeln!(out, "{pad}    {accessor};");
                continue;
            }
            match self.body_block(ty, method) {
                Some(block) => {
                    let _ = writeln!(out, "{pad}    {accessor}");
                    for line in block.lines() {
                        let _ = writeln!(out, "{pad}    {line}");
                    }
                }
                None => {
                    self.refusals.push(Refusal {
                        type_name: ty.full_name.clone(),
                        member: method.name.clone(),
                        reason: "the decompiler produced no body for this accessor".to_owned(),
                    });
                }
            }
        }
        let _ = writeln!(out, "{pad}}}");
    }

    fn field_declaration(&self, field: &FieldModel) -> String {
        let accessibility: &str = match field.flags & FIELD_ACCESS_MASK {
            2 => "private protected",
            3 => "internal",
            4 => "protected",
            5 => "protected internal",
            6 => "public",
            _ => "private",
        };
        let is_literal: bool = field.flags & FIELD_LITERAL != 0;
        let mut modifiers: Vec<&str> = vec![accessibility];
        if is_literal {
            modifiers.push("const");
        } else {
            if field.flags & FIELD_STATIC != 0 {
                modifiers.push("static");
            }
            if field.flags & FIELD_INIT_ONLY != 0 {
                modifiers.push("readonly");
            }
            if field.is_volatile {
                modifiers.push("volatile");
            }
        }
        let name: String = member_identifier(&field.name);
        if let Some((clr_name, length)) = self.resolver.field_fixed_buffer_info(field.token)
            && let Some(keyword) =
                fixed_buffer_keyword(clr_name.split(',').next().unwrap_or(&clr_name).trim())
        {
            return format!(
                "{} unsafe fixed {keyword} {name}[{length}];",
                modifiers.join(" ")
            );
        }
        let field_type: String = self
            .resolver
            .render_type(&field.field_type, TargetLang::CSharp);
        let initializer: String = match (&field.constant, is_literal) {
            (Some(constant), true) => format!(" = {}", csharp_constant(constant)),
            _ => String::new(),
        };
        format!("{} {field_type} {name}{initializer};", modifiers.join(" "))
    }
}

fn backing_property_name(field_name: &str) -> Option<&str> {
    let inner: &str = field_name
        .strip_prefix('<')?
        .strip_suffix(BACKING_FIELD_SUFFIX)?;
    (!inner.is_empty()).then_some(inner)
}

fn fixed_buffer_keyword(clr_name: &str) -> Option<&'static str> {
    Some(match clr_name {
        "System.Boolean" => "bool",
        "System.Byte" => "byte",
        "System.SByte" => "sbyte",
        "System.Char" => "char",
        "System.Int16" => "short",
        "System.UInt16" => "ushort",
        "System.Int32" => "int",
        "System.UInt32" => "uint",
        "System.Int64" => "long",
        "System.UInt64" => "ulong",
        "System.Single" => "float",
        "System.Double" => "double",
        _ => return None,
    })
}

fn operator_symbol(name: &str) -> Option<&'static str> {
    Some(match name {
        "op_Addition" | "op_UnaryPlus" => "+",
        "op_Subtraction" | "op_UnaryNegation" => "-",
        "op_Multiply" => "*",
        "op_Division" => "/",
        "op_Modulus" => "%",
        "op_Equality" => "==",
        "op_Inequality" => "!=",
        "op_LessThan" => "<",
        "op_GreaterThan" => ">",
        "op_LessThanOrEqual" => "<=",
        "op_GreaterThanOrEqual" => ">=",
        "op_BitwiseAnd" => "&",
        "op_BitwiseOr" => "|",
        "op_ExclusiveOr" => "^",
        "op_LeftShift" => "<<",
        "op_RightShift" => ">>",
        "op_LogicalNot" => "!",
        "op_OnesComplement" => "~",
        "op_Increment" => "++",
        "op_Decrement" => "--",
        "op_True" => "true",
        "op_False" => "false",
        _ => return None,
    })
}

fn le_bytes<const LENGTH: usize>(constant: &FieldConstant) -> [u8; LENGTH] {
    let mut out: [u8; LENGTH] = [0u8; LENGTH];
    for (slot, byte) in out.iter_mut().zip(constant.value.iter()) {
        *slot = *byte;
    }
    out
}

fn csharp_string_literal(units: &[u16]) -> String {
    let mut out: String = String::from("\"");
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok('"') => out.push_str("\\\""),
            Ok('\\') => out.push_str("\\\\"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok('\t') => out.push_str("\\t"),
            Ok(c) if (c as u32) < 0x20 || disrobe_core::source_text::is_unsafe_in_source(c) => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            Ok(c) => out.push(c),
            Err(e) => {
                let _ = write!(out, "\\u{:04X}", e.unpaired_surrogate());
            }
        }
    }
    out.push('"');
    out
}

#[must_use]
pub fn csharp_constant(constant: &FieldConstant) -> String {
    match constant.element_type {
        0x02 => (constant.value.first().copied().unwrap_or(0) != 0).to_string(),
        0x03 => {
            let unit: u16 = u16::from_le_bytes(le_bytes::<2>(constant));
            match char::from_u32(u32::from(unit)) {
                Some(c) if c != '\'' && c != '\\' && (c as u32) >= 0x20 => format!("'{c}'"),
                _ => format!("'\\u{unit:04X}'"),
            }
        }
        0x04 => i8::from_le_bytes(le_bytes::<1>(constant)).to_string(),
        0x05 => u8::from_le_bytes(le_bytes::<1>(constant)).to_string(),
        0x06 => i16::from_le_bytes(le_bytes::<2>(constant)).to_string(),
        0x07 => u16::from_le_bytes(le_bytes::<2>(constant)).to_string(),
        0x08 => i32::from_le_bytes(le_bytes::<4>(constant)).to_string(),
        0x09 => format!("{}u", u32::from_le_bytes(le_bytes::<4>(constant))),
        0x0A => format!("{}L", i64::from_le_bytes(le_bytes::<8>(constant))),
        0x0B => format!("{}UL", u64::from_le_bytes(le_bytes::<8>(constant))),
        0x0C => {
            let v: f32 = f32::from_le_bytes(le_bytes::<4>(constant));
            if v.is_finite() {
                format!("{v:?}f")
            } else {
                "float.NaN".to_owned()
            }
        }
        0x0D => {
            let v: f64 = f64::from_le_bytes(le_bytes::<8>(constant));
            if v.is_finite() {
                format!("{v:?}d")
            } else {
                "double.NaN".to_owned()
            }
        }
        0x0E => {
            let units: Vec<u16> = constant
                .value
                .chunks_exact(2)
                .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            csharp_string_literal(&units)
        }
        _ => "null".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_repaired_deterministically() {
        assert_eq!(
            member_identifier("Log get_Syntax Load.FixedUpdate"),
            "Log_get_Syntax_Load_FixedUpdate"
        );
        assert_eq!(member_identifier("6"), "_6");
        assert_eq!(member_identifier("class"), "@class");
        assert_eq!(type_identifier("Dictionary`2"), "Dictionary");
        assert_eq!(namespace_identifier("A.B c"), "A.B_c");
    }

    #[test]
    fn constants_render_as_csharp_literals() {
        let text: FieldConstant = FieldConstant {
            element_type: 0x0E,
            value: "a\"b".encode_utf16().flat_map(u16::to_le_bytes).collect(),
        };
        assert_eq!(csharp_constant(&text), "\"a\\\"b\"");
        let int: FieldConstant = FieldConstant {
            element_type: 0x08,
            value: 31i32.to_le_bytes().to_vec(),
        };
        assert_eq!(csharp_constant(&int), "31");
    }
}
