use serde::{Deserialize, Serialize};

use crate::macho::{self, ParsedSlice, Section, SliceView};
use crate::swift_reflect::{self, FieldDescriptorKind, SwiftField};

const TYPE_CONTEXT_KIND_MASK: u32 = 0x1F;
const CONTEXT_KIND_MODULE: u32 = 0x00;
const CONTEXT_KIND_PROTOCOL: u32 = 0x03;
const CONTEXT_KIND_CLASS: u32 = 0x10;
const CONTEXT_KIND_STRUCT: u32 = 0x11;
const CONTEXT_KIND_ENUM: u32 = 0x12;

const TYPE_FLAGS_KIND_SPECIFIC_SHIFT: u32 = 16;
const CLASS_HAS_RESILIENT_SUPERCLASS: u16 = 0x2000;
const CLASS_HAS_SUPERCLASS_TYPEREF: u16 = 0x4000;

const RELATIVE_PTR_WORD: usize = 4;
const TYPE_DESCRIPTOR_FIXED_FIELDS: usize = 5;
const CONFORMANCE_RECORD_MIN: usize = 16;
const ASSOCTY_HEADER: usize = 16;
const ASSOCTY_RECORD: usize = 8;

const PROTOCOL_NUM_REQ_SIG_OFF: usize = 3 * RELATIVE_PTR_WORD;
const PROTOCOL_NUM_REQ_OFF: usize = 4 * RELATIVE_PTR_WORD;
const PROTOCOL_ASSOC_NAMES_OFF: usize = 5 * RELATIVE_PTR_WORD;
const PROTOCOL_HEADER_WORDS: usize = 6;
const GENERIC_REQUIREMENT_SIZE: usize = 8;
const PROTOCOL_REQUIREMENT_SIZE: usize = 12;
const PROTOCOL_REQUIREMENT_KIND_MASK: u32 = 0x0F;
const PROTOCOL_REQUIREMENT_INSTANCE_BIT: u32 = 0x10;
const MAX_PROTOCOL_REQUIREMENTS: usize = 1 << 14;

const MAX_NAME_LEN: usize = 4096;
const MAX_TYPE_RECORDS: usize = 1 << 16;
const MAX_PARENT_WALK: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NominalKind {
    Class,
    Struct,
    Enum,
    Other(u32),
}

impl NominalKind {
    #[must_use]
    pub const fn from_context_flags(flags: u32) -> Self {
        match flags & TYPE_CONTEXT_KIND_MASK {
            CONTEXT_KIND_CLASS => Self::Class,
            CONTEXT_KIND_STRUCT => Self::Struct,
            CONTEXT_KIND_ENUM => Self::Enum,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Other(_) => "type",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftNominalType {
    pub kind: NominalKind,
    pub name: String,
    pub qualified_name: String,
    pub fields: Vec<SwiftField>,
    pub superclass: Option<String>,
    pub conformances: Vec<String>,
    pub descriptor_offset: u64,
}

impl SwiftNominalType {
    #[must_use]
    pub fn render(&self) -> String {
        let kw: &str = self.kind.keyword();
        let mut inherits: Vec<String> = Vec::new();
        if let Some(sup) = self.superclass.as_deref() {
            inherits.push(sup.to_owned());
        }
        for proto in &self.conformances {
            inherits.push(proto.clone());
        }
        let mut out: String = String::new();
        out.push_str(kw);
        out.push(' ');
        out.push_str(&self.qualified_name);
        if !inherits.is_empty() {
            out.push_str(" : ");
            out.push_str(&inherits.join(", "));
        }
        out.push_str(" {\n");
        let is_enum: bool = matches!(self.kind, NominalKind::Enum);
        for field in &self.fields {
            if is_enum {
                out.push_str("    case ");
                out.push_str(&field.name);
                if field.mangled_type.is_some() {
                    out.push('(');
                    out.push_str(&field.display_type());
                    out.push(')');
                }
            } else {
                let decl: &str = if field.is_var { "var" } else { "let" };
                let ty: String = field.display_type();
                out.push_str("    ");
                out.push_str(decl);
                out.push(' ');
                out.push_str(&field.name);
                out.push_str(": ");
                out.push_str(&ty);
            }
            out.push('\n');
        }
        out.push_str("}\n");
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConformanceProtocolKind {
    InModule,
    External,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftProtocolConformance {
    pub protocol_name: Option<String>,
    pub protocol_kind: ConformanceProtocolKind,
    pub conforming_type: Option<String>,
    pub has_witness_table: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftAssociatedTypeWitness {
    pub name: String,
    pub substituted_mangled_type: String,
    pub substituted_demangled_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftAssociatedTypeRecord {
    pub conforming_type_mangled: Option<String>,
    pub protocol_mangled: Option<String>,
    pub witnesses: Vec<SwiftAssociatedTypeWitness>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolRequirementKind {
    BaseProtocol,
    Method,
    Init,
    Getter,
    Setter,
    ReadCoroutine,
    WriteCoroutine,
    ModifyCoroutine,
    AssociatedTypeAccessFunction,
    AssociatedConformanceAccessFunction,
    Other(u32),
}

impl ProtocolRequirementKind {
    #[must_use]
    pub const fn from_flags(flags: u32) -> Self {
        match flags & PROTOCOL_REQUIREMENT_KIND_MASK {
            0 => Self::BaseProtocol,
            1 => Self::Method,
            2 => Self::Init,
            3 => Self::Getter,
            4 => Self::Setter,
            5 => Self::ReadCoroutine,
            6 => Self::WriteCoroutine,
            7 => Self::ModifyCoroutine,
            8 => Self::AssociatedTypeAccessFunction,
            9 => Self::AssociatedConformanceAccessFunction,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BaseProtocol => "inherited protocol",
            Self::Method => "func",
            Self::Init => "init",
            Self::Getter => "get",
            Self::Setter => "set",
            Self::ReadCoroutine => "_read",
            Self::WriteCoroutine => "_write",
            Self::ModifyCoroutine => "_modify",
            Self::AssociatedTypeAccessFunction => "associatedtype",
            Self::AssociatedConformanceAccessFunction => "associated conformance",
            Self::Other(_) => "requirement",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftProtocolRequirement {
    pub kind: ProtocolRequirementKind,
    pub is_instance: bool,
    pub has_default_implementation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftProtocolDescriptor {
    pub name: String,
    pub qualified_name: String,
    pub descriptor_offset: u64,
    pub num_requirements_in_signature: u32,
    pub requirements: Vec<SwiftProtocolRequirement>,
    pub associated_type_names: Vec<String>,
}

impl SwiftProtocolDescriptor {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::new();
        out.push_str("protocol ");
        out.push_str(&self.qualified_name);
        out.push_str(" {\n");
        for assoc in &self.associated_type_names {
            out.push_str("    associatedtype ");
            out.push_str(assoc);
            out.push('\n');
        }
        for req in &self.requirements {
            let scope: &str = if req.is_instance { "" } else { "static " };
            let suffix: &str = if req.has_default_implementation {
                " { /* has default */ }"
            } else {
                ""
            };
            match req.kind {
                ProtocolRequirementKind::Method | ProtocolRequirementKind::Init => {
                    out.push_str("    ");
                    out.push_str(scope);
                    out.push_str(req.kind.label());
                    out.push_str(suffix);
                    out.push('\n');
                }
                ProtocolRequirementKind::Getter
                | ProtocolRequirementKind::Setter
                | ProtocolRequirementKind::ReadCoroutine
                | ProtocolRequirementKind::WriteCoroutine
                | ProtocolRequirementKind::ModifyCoroutine => {
                    out.push_str("    ");
                    out.push_str(scope);
                    out.push_str("var { ");
                    out.push_str(req.kind.label());
                    out.push_str(" }");
                    out.push_str(suffix);
                    out.push('\n');
                }
                ProtocolRequirementKind::AssociatedTypeAccessFunction => {}
                other => {
                    out.push_str("    ");
                    out.push_str(other.label());
                    out.push_str(suffix);
                    out.push('\n');
                }
            }
        }
        out.push_str("}\n");
        out
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwiftTypeDump {
    pub nominal_types: Vec<SwiftNominalType>,
    pub protocols: Vec<SwiftProtocolDescriptor>,
    pub conformances: Vec<SwiftProtocolConformance>,
    pub associated_types: Vec<SwiftAssociatedTypeRecord>,
}

impl SwiftTypeDump {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nominal_types.is_empty()
            && self.protocols.is_empty()
            && self.conformances.is_empty()
            && self.associated_types.is_empty()
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut out: String = String::new();
        for proto in &self.protocols {
            out.push_str(&proto.render());
        }
        if !self.protocols.is_empty() {
            out.push('\n');
        }
        for ty in &self.nominal_types {
            out.push_str(&ty.render());
            out.push('\n');
        }
        for assoc in &self.associated_types {
            if assoc.witnesses.is_empty() {
                continue;
            }
            let conformer: &str = assoc.conforming_type_mangled.as_deref().unwrap_or("<type>");
            let proto: &str = assoc.protocol_mangled.as_deref().unwrap_or("<protocol>");
            out.push_str("extension ");
            out.push_str(conformer);
            out.push_str(" : ");
            out.push_str(proto);
            out.push_str(" {\n");
            for w in &assoc.witnesses {
                let ty: &str = w
                    .substituted_demangled_type
                    .as_deref()
                    .unwrap_or(&w.substituted_mangled_type);
                out.push_str("    typealias ");
                out.push_str(&w.name);
                out.push_str(" = ");
                out.push_str(ty);
                out.push('\n');
            }
            out.push_str("}\n");
        }
        out
    }
}

fn read_qualified_name(view: &SliceView<'_>, descriptor_off: usize) -> (String, String) {
    let name_field: usize = descriptor_off + 2 * RELATIVE_PTR_WORD;
    let name: String = view
        .resolve_relative(name_field)
        .and_then(|t: usize| view.cstr_at_offset(t, MAX_NAME_LEN))
        .filter(|s: &String| s.bytes().all(|b: u8| b >= 0x20))
        .unwrap_or_default();
    let parent_chain: Vec<String> = walk_parent_names(view, descriptor_off);
    let mut qualified: String = String::new();
    for segment in &parent_chain {
        qualified.push_str(segment);
        qualified.push('.');
    }
    qualified.push_str(&name);
    (name, qualified)
}

fn walk_parent_names(view: &SliceView<'_>, descriptor_off: usize) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cursor: usize = descriptor_off;
    let mut guard: usize = 0;
    loop {
        if guard >= MAX_PARENT_WALK {
            break;
        }
        guard += 1;
        let parent_field: usize = cursor + RELATIVE_PTR_WORD;
        let Some((parent_off, indirect)): Option<(usize, bool)> =
            view.resolve_indirectable_relative(parent_field)
        else {
            break;
        };
        if indirect {
            break;
        }
        let Some(parent_flags): Option<u32> = view.read_u32_at(parent_off) else {
            break;
        };
        let parent_kind: u32 = parent_flags & TYPE_CONTEXT_KIND_MASK;
        let pname_field: usize = parent_off + 2 * RELATIVE_PTR_WORD;
        if let Some(pname) = view
            .resolve_relative(pname_field)
            .and_then(|t: usize| view.cstr_at_offset(t, MAX_NAME_LEN))
            .filter(|s: &String| !s.is_empty() && s.bytes().all(|b: u8| b >= 0x20))
        {
            names.push(pname);
        }
        if parent_kind == CONTEXT_KIND_MODULE {
            break;
        }
        cursor = parent_off;
    }
    names.reverse();
    names
}

fn read_class_superclass(
    view: &SliceView<'_>,
    descriptor_off: usize,
    type_flags: u32,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let kind_specific: u16 = (type_flags >> TYPE_FLAGS_KIND_SPECIFIC_SHIFT) as u16;
    if kind_specific & CLASS_HAS_RESILIENT_SUPERCLASS != 0 {
        return None;
    }
    if kind_specific & CLASS_HAS_SUPERCLASS_TYPEREF == 0 {
        return None;
    }
    let superclass_field: usize = descriptor_off + TYPE_DESCRIPTOR_FIXED_FIELDS * RELATIVE_PTR_WORD;
    let target: usize = view.resolve_relative(superclass_field)?;
    let mangled: String = view.cstr_at_offset(target, MAX_NAME_LEN)?;
    if mangled.is_empty() {
        return None;
    }
    if let Some(d) = demangle(&mangled) {
        return Some(d);
    }
    if mangled.bytes().any(|b: u8| b < 0x20) {
        return None;
    }
    Some(mangled)
}

fn read_fields_for_descriptor(
    view: &SliceView<'_>,
    descriptor_off: usize,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Vec<SwiftField> {
    let field_link: usize = descriptor_off + 4 * RELATIVE_PTR_WORD;
    let Some(fieldmd_off): Option<usize> = view.resolve_relative(field_link) else {
        return Vec::new();
    };
    swift_reflect::read_field_list(view, fieldmd_off, demangle)
}

#[must_use]
fn parse_nominal_types(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Vec<SwiftNominalType> {
    let Some(section): Option<&Section> = macho::find_section(parsed, "__TEXT", "__swift5_types")
    else {
        return Vec::new();
    };
    let sect_start: usize = section.offset as usize;
    let Ok(sect_len): core::result::Result<usize, _> = usize::try_from(section.size) else {
        return Vec::new();
    };
    let count: usize = (sect_len / RELATIVE_PTR_WORD).min(MAX_TYPE_RECORDS);
    let mut out: Vec<SwiftNominalType> = Vec::with_capacity(count);
    for i in 0..count {
        let row_off: usize = sect_start + i * RELATIVE_PTR_WORD;
        let Some(descriptor_off): Option<usize> = view.resolve_relative(row_off) else {
            continue;
        };
        let Some(type_flags): Option<u32> = view.read_u32_at(descriptor_off) else {
            continue;
        };
        let kind: NominalKind = NominalKind::from_context_flags(type_flags);
        if matches!(kind, NominalKind::Other(_)) {
            continue;
        }
        let (name, qualified_name): (String, String) = read_qualified_name(view, descriptor_off);
        if name.is_empty() {
            continue;
        }
        let fields: Vec<SwiftField> = read_fields_for_descriptor(view, descriptor_off, demangle);
        let superclass: Option<String> = if matches!(kind, NominalKind::Class) {
            read_class_superclass(view, descriptor_off, type_flags, demangle)
        } else {
            None
        };
        out.push(SwiftNominalType {
            kind,
            name,
            qualified_name,
            fields,
            superclass,
            conformances: Vec::new(),
            descriptor_offset: descriptor_off as u64,
        });
    }
    out
}

#[must_use]
fn parse_protocol_descriptors(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
) -> Vec<SwiftProtocolDescriptor> {
    let Some(section): Option<&Section> = macho::find_section(parsed, "__TEXT", "__swift5_protos")
    else {
        return Vec::new();
    };
    let sect_start: usize = section.offset as usize;
    let Ok(sect_len): core::result::Result<usize, _> = usize::try_from(section.size) else {
        return Vec::new();
    };
    let count: usize = (sect_len / RELATIVE_PTR_WORD).min(MAX_TYPE_RECORDS);
    let mut out: Vec<SwiftProtocolDescriptor> = Vec::with_capacity(count);
    for i in 0..count {
        let row_off: usize = sect_start + i * RELATIVE_PTR_WORD;
        let Some(descriptor_off): Option<usize> = view.resolve_relative(row_off) else {
            continue;
        };
        let (name, qualified_name): (String, String) = read_qualified_name(view, descriptor_off);
        if name.is_empty() {
            continue;
        }
        let num_requirements_in_signature: u32 = view
            .read_u32_at(descriptor_off + PROTOCOL_NUM_REQ_SIG_OFF)
            .unwrap_or(0);
        let requirements: Vec<SwiftProtocolRequirement> =
            read_protocol_requirements(view, descriptor_off, num_requirements_in_signature);
        let associated_type_names: Vec<String> =
            read_associated_type_names(view, descriptor_off + PROTOCOL_ASSOC_NAMES_OFF);
        out.push(SwiftProtocolDescriptor {
            name,
            qualified_name,
            descriptor_offset: descriptor_off as u64,
            num_requirements_in_signature,
            requirements,
            associated_type_names,
        });
    }
    out
}

fn read_associated_type_names(view: &SliceView<'_>, field_off: usize) -> Vec<String> {
    let Some(target): Option<usize> = view.resolve_relative(field_off) else {
        return Vec::new();
    };
    let Some(blob): Option<String> = view.cstr_at_offset(target, MAX_NAME_LEN) else {
        return Vec::new();
    };
    blob.split_whitespace()
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn read_protocol_requirements(
    view: &SliceView<'_>,
    descriptor_off: usize,
    num_requirements_in_signature: u32,
) -> Vec<SwiftProtocolRequirement> {
    let Some(num_requirements): Option<u32> =
        view.read_u32_at(descriptor_off + PROTOCOL_NUM_REQ_OFF)
    else {
        return Vec::new();
    };
    let count: usize = (num_requirements as usize).min(MAX_PROTOCOL_REQUIREMENTS);
    let sig_words: usize = (num_requirements_in_signature as usize)
        .min(MAX_PROTOCOL_REQUIREMENTS)
        .saturating_mul(GENERIC_REQUIREMENT_SIZE / RELATIVE_PTR_WORD);
    let Some(req_base): Option<usize> = descriptor_off
        .checked_add(PROTOCOL_HEADER_WORDS * RELATIVE_PTR_WORD)
        .and_then(|h: usize| h.checked_add(sig_words * RELATIVE_PTR_WORD))
    else {
        return Vec::new();
    };
    let Some(req_end): Option<usize> =
        req_base.checked_add(count.saturating_mul(PROTOCOL_REQUIREMENT_SIZE))
    else {
        return Vec::new();
    };
    if req_end > view.bytes().len() {
        return Vec::new();
    }
    let mut out: Vec<SwiftProtocolRequirement> = Vec::with_capacity(count);
    for i in 0..count {
        let rec_off: usize = req_base + i * PROTOCOL_REQUIREMENT_SIZE;
        let Some(flags): Option<u32> = view.read_u32_at(rec_off) else {
            break;
        };
        let default_field: usize = rec_off + RELATIVE_PTR_WORD;
        let has_default_implementation: bool = view
            .read_i32_at(default_field)
            .is_some_and(|rel: i32| rel != 0);
        out.push(SwiftProtocolRequirement {
            kind: ProtocolRequirementKind::from_flags(flags),
            is_instance: flags & PROTOCOL_REQUIREMENT_INSTANCE_BIT != 0,
            has_default_implementation,
        });
    }
    out
}

#[must_use]
fn parse_conformances(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    protocols: &[SwiftProtocolDescriptor],
) -> Vec<SwiftProtocolConformance> {
    let Some(section): Option<&Section> = macho::find_section(parsed, "__TEXT", "__swift5_proto")
    else {
        return Vec::new();
    };
    let sect_start: usize = section.offset as usize;
    let Ok(sect_len): core::result::Result<usize, _> = usize::try_from(section.size) else {
        return Vec::new();
    };
    let count: usize = (sect_len / RELATIVE_PTR_WORD).min(MAX_TYPE_RECORDS);
    let mut out: Vec<SwiftProtocolConformance> = Vec::with_capacity(count);
    for i in 0..count {
        let row_off: usize = sect_start + i * RELATIVE_PTR_WORD;
        let Some(conf_off): Option<usize> = view.resolve_relative(row_off) else {
            continue;
        };
        if conf_off + CONFORMANCE_RECORD_MIN > view.bytes().len() {
            continue;
        }
        let flags: u32 = view
            .read_u32_at(conf_off + 3 * RELATIVE_PTR_WORD)
            .unwrap_or(0);
        let type_ref_kind: u32 = (flags >> 3) & 0x3;
        let (protocol_name, protocol_kind): (Option<String>, ConformanceProtocolKind) =
            resolve_conformance_protocol(view, conf_off, protocols);
        let conforming_type: Option<String> =
            resolve_conformance_type(view, conf_off + RELATIVE_PTR_WORD, type_ref_kind);
        let witness_field: usize = conf_off + 2 * RELATIVE_PTR_WORD;
        let has_witness_table: bool = view.read_i32_at(witness_field).is_some_and(|w: i32| w != 0);
        out.push(SwiftProtocolConformance {
            protocol_name,
            protocol_kind,
            conforming_type,
            has_witness_table,
        });
    }
    out
}

fn resolve_conformance_protocol(
    view: &SliceView<'_>,
    conf_off: usize,
    protocols: &[SwiftProtocolDescriptor],
) -> (Option<String>, ConformanceProtocolKind) {
    let Some((proto_off, indirect)): Option<(usize, bool)> =
        view.resolve_indirectable_relative(conf_off)
    else {
        return (None, ConformanceProtocolKind::Unresolved);
    };
    if indirect {
        return (None, ConformanceProtocolKind::External);
    }
    if let Some(p) = protocols
        .iter()
        .find(|p: &&SwiftProtocolDescriptor| p.descriptor_offset == proto_off as u64)
    {
        return (
            Some(p.qualified_name.clone()),
            ConformanceProtocolKind::InModule,
        );
    }
    let name_field: usize = proto_off + 2 * RELATIVE_PTR_WORD;
    let name: Option<String> = view
        .resolve_relative(name_field)
        .and_then(|t: usize| view.cstr_at_offset(t, MAX_NAME_LEN))
        .filter(|s: &String| !s.is_empty() && s.bytes().all(|b: u8| b >= 0x20));
    name.map_or((None, ConformanceProtocolKind::External), |n: String| {
        (Some(n), ConformanceProtocolKind::InModule)
    })
}

fn resolve_conformance_type(
    view: &SliceView<'_>,
    type_ref_field: usize,
    type_ref_kind: u32,
) -> Option<String> {
    match type_ref_kind {
        0 => {
            let (desc_off, indirect): (usize, bool) =
                view.resolve_indirectable_relative(type_ref_field)?;
            if indirect {
                return None;
            }
            let (_, qualified): (String, String) = read_qualified_name(view, desc_off);
            if qualified.is_empty() {
                None
            } else {
                Some(qualified)
            }
        }
        2 | 3 => {
            let target: usize = view.resolve_relative(type_ref_field)?;
            let mangled: String = view.cstr_at_offset(target, MAX_NAME_LEN)?;
            if mangled.is_empty() || mangled.bytes().any(|b: u8| b < 0x20) {
                None
            } else {
                Some(mangled)
            }
        }
        _ => None,
    }
}

#[must_use]
fn parse_associated_types(
    view: &SliceView<'_>,
    parsed: &ParsedSlice,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> Vec<SwiftAssociatedTypeRecord> {
    let Some(section): Option<&Section> = macho::find_section(parsed, "__TEXT", "__swift5_assocty")
    else {
        return Vec::new();
    };
    let sect_start: usize = section.offset as usize;
    let Ok(sect_len): core::result::Result<usize, _> = usize::try_from(section.size) else {
        return Vec::new();
    };
    let Some(sect_end): Option<usize> = sect_start.checked_add(sect_len) else {
        return Vec::new();
    };
    if sect_end > view.bytes().len() {
        return Vec::new();
    }
    let mut out: Vec<SwiftAssociatedTypeRecord> = Vec::new();
    let mut cursor: usize = sect_start;
    let mut guard: usize = 0;
    while cursor + ASSOCTY_HEADER <= sect_end && guard < MAX_TYPE_RECORDS {
        guard += 1;
        let conforming_type_mangled: Option<String> = rel_clean_string(view, cursor);
        let protocol_mangled: Option<String> = rel_clean_string(view, cursor + RELATIVE_PTR_WORD);
        let Some(num_witnesses): Option<u32> = view.read_u32_at(cursor + 2 * RELATIVE_PTR_WORD)
        else {
            break;
        };
        let Some(record_size): Option<u32> = view.read_u32_at(cursor + 3 * RELATIVE_PTR_WORD)
        else {
            break;
        };
        let elem_size: usize = if record_size == 0 {
            ASSOCTY_RECORD
        } else {
            record_size as usize
        };
        let witness_count: usize = (num_witnesses as usize).min(MAX_TYPE_RECORDS);
        let body_bytes: usize = witness_count.saturating_mul(elem_size);
        let record_end: usize = cursor + ASSOCTY_HEADER + body_bytes;
        if record_end > sect_end {
            break;
        }
        let mut witnesses: Vec<SwiftAssociatedTypeWitness> = Vec::with_capacity(witness_count);
        for w in 0..witness_count {
            let rec: usize = cursor + ASSOCTY_HEADER + w * elem_size;
            let name: Option<String> = rel_clean_string(view, rec);
            let substituted: Option<String> = view
                .resolve_relative(rec + RELATIVE_PTR_WORD)
                .and_then(|t: usize| view.cstr_at_offset(t, MAX_NAME_LEN));
            if let (Some(n), Some(sub)) = (name, substituted) {
                let demangled: Option<String> = demangle(&sub).filter(|d: &String| d != &sub);
                witnesses.push(SwiftAssociatedTypeWitness {
                    name: n,
                    substituted_mangled_type: sub,
                    substituted_demangled_type: demangled,
                });
            }
        }
        out.push(SwiftAssociatedTypeRecord {
            conforming_type_mangled,
            protocol_mangled,
            witnesses,
        });
        cursor = record_end;
    }
    out
}

fn rel_clean_string(view: &SliceView<'_>, field_off: usize) -> Option<String> {
    let target: usize = view.resolve_relative(field_off)?;
    let s: String = view.cstr_at_offset(target, MAX_NAME_LEN)?;
    if s.is_empty() || s.bytes().any(|b: u8| b < 0x20) {
        None
    } else {
        Some(s)
    }
}

fn attach_conformances(types: &mut [SwiftNominalType], conformances: &[SwiftProtocolConformance]) {
    for conf in conformances {
        let (Some(type_name), Some(proto)): (Option<&String>, Option<&String>) =
            (conf.conforming_type.as_ref(), conf.protocol_name.as_ref())
        else {
            continue;
        };
        if let Some(ty) = types.iter_mut().find(|t: &&mut SwiftNominalType| {
            &t.qualified_name == type_name || &t.name == type_name
        }) && !ty.conformances.contains(proto)
        {
            ty.conformances.push(proto.clone());
        }
    }
}

#[must_use]
pub fn parse_type_dump(
    slice: &[u8],
    parsed: &ParsedSlice,
    demangle: &dyn Fn(&str) -> Option<String>,
) -> SwiftTypeDump {
    let Some(view): Option<SliceView<'_>> = SliceView::new(slice, parsed) else {
        return SwiftTypeDump::default();
    };
    let protocols: Vec<SwiftProtocolDescriptor> = parse_protocol_descriptors(&view, parsed);
    let mut nominal_types: Vec<SwiftNominalType> = parse_nominal_types(&view, parsed, demangle);
    let conformances: Vec<SwiftProtocolConformance> = parse_conformances(&view, parsed, &protocols);
    let associated_types: Vec<SwiftAssociatedTypeRecord> =
        parse_associated_types(&view, parsed, demangle);
    attach_conformances(&mut nominal_types, &conformances);
    SwiftTypeDump {
        nominal_types,
        protocols,
        conformances,
        associated_types,
    }
}

#[must_use]
pub const fn nominal_kind_for(kind: FieldDescriptorKind) -> NominalKind {
    match kind {
        FieldDescriptorKind::Struct => NominalKind::Struct,
        FieldDescriptorKind::Class | FieldDescriptorKind::ObjcClass => NominalKind::Class,
        FieldDescriptorKind::Enum | FieldDescriptorKind::MultiPayloadEnum => NominalKind::Enum,
        FieldDescriptorKind::Protocol
        | FieldDescriptorKind::ClassProtocol
        | FieldDescriptorKind::ObjcProtocol => NominalKind::Other(CONTEXT_KIND_PROTOCOL),
        FieldDescriptorKind::Unknown(other) => NominalKind::Other(other as u32),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nominal_kind_decodes_context_flags() {
        assert_eq!(
            NominalKind::from_context_flags(0x8000_0050),
            NominalKind::Class
        );
        assert_eq!(NominalKind::from_context_flags(0x51), NominalKind::Struct);
        assert_eq!(NominalKind::from_context_flags(0x52), NominalKind::Enum);
        assert_eq!(NominalKind::from_context_flags(0x42), NominalKind::Other(2));
    }

    #[test]
    fn render_struct_with_conformance_and_fields() {
        let ty: SwiftNominalType = SwiftNominalType {
            kind: NominalKind::Struct,
            name: "Receipt".to_owned(),
            qualified_name: "App.Receipt".to_owned(),
            fields: vec![SwiftField {
                name: "id".to_owned(),
                mangled_type: Some("SS".to_owned()),
                demangled_type: Some("Swift.String".to_owned()),
                is_indirect_enum_case: false,
                is_var: false,
            }],
            superclass: None,
            conformances: vec!["App.Codable".to_owned()],
            descriptor_offset: 0,
        };
        let r: String = ty.render();
        assert!(r.starts_with("struct App.Receipt : App.Codable {"));
        assert!(r.contains("let id: Swift.String"));
    }

    #[test]
    fn requirement_kind_decodes_flags() {
        assert_eq!(
            ProtocolRequirementKind::from_flags(0x11),
            ProtocolRequirementKind::Method
        );
        assert_eq!(
            ProtocolRequirementKind::from_flags(0x13),
            ProtocolRequirementKind::Getter
        );
        assert_eq!(
            ProtocolRequirementKind::from_flags(0x00),
            ProtocolRequirementKind::BaseProtocol
        );
        assert_eq!(
            ProtocolRequirementKind::from_flags(0x0F),
            ProtocolRequirementKind::Other(15)
        );
    }

    #[test]
    fn protocol_render_emits_requirement_body() {
        let proto: SwiftProtocolDescriptor = SwiftProtocolDescriptor {
            name: "Greeter".to_owned(),
            qualified_name: "App.Greeter".to_owned(),
            descriptor_offset: 0,
            num_requirements_in_signature: 0,
            requirements: vec![
                SwiftProtocolRequirement {
                    kind: ProtocolRequirementKind::Method,
                    is_instance: true,
                    has_default_implementation: false,
                },
                SwiftProtocolRequirement {
                    kind: ProtocolRequirementKind::Getter,
                    is_instance: true,
                    has_default_implementation: true,
                },
            ],
            associated_type_names: vec!["Element".to_owned()],
        };
        let r: String = proto.render();
        assert!(r.starts_with("protocol App.Greeter {"));
        assert!(r.contains("    associatedtype Element"));
        assert!(r.contains("    func"));
        assert!(r.contains("var { get } { /* has default */ }"));
        assert!(r.trim_end().ends_with('}'));
    }

    #[test]
    fn render_class_with_superclass_then_protocols() {
        let ty: SwiftNominalType = SwiftNominalType {
            kind: NominalKind::Class,
            name: "View".to_owned(),
            qualified_name: "App.View".to_owned(),
            fields: Vec::new(),
            superclass: Some("UIKit.UIView".to_owned()),
            conformances: vec!["App.Greeter".to_owned()],
            descriptor_offset: 0,
        };
        let r: String = ty.render();
        assert!(r.starts_with("class App.View : UIKit.UIView, App.Greeter {"));
    }
}
