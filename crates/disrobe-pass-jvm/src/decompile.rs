use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bytecode::{
    self, CodeAttribute, Instruction, Operands, branch_target, disassemble, parse_code_attribute,
    validate_code_attribute,
};
use crate::classfile::{ClassFile, ConstantPoolEntry, FieldInfo, MethodInfo};
use crate::decompile_struct::{
    BasicBlock, BlockId, Cfg, Dominators, EdgeKind, ExceptionRegion, NaturalLoop, Region,
    Structurer, SwitchKey, build_cfg, compute_dominators, find_natural_loops,
};
use crate::descriptor::{self, JavaType, MethodDescriptor};
use crate::error::{Error, Result};
use crate::frame_infer::{DeferredAllocationPlan, plan_deferred_allocations};

pub const ACC_PUBLIC: u16 = 0x0001;
pub const ACC_PRIVATE: u16 = 0x0002;
pub const ACC_PROTECTED: u16 = 0x0004;
pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_FINAL: u16 = 0x0010;
pub const ACC_SYNCHRONIZED: u16 = 0x0020;
pub const ACC_VOLATILE: u16 = 0x0040;
pub const ACC_TRANSIENT: u16 = 0x0080;
pub const ACC_VARARGS: u16 = 0x0080;
pub const ACC_NATIVE: u16 = 0x0100;
pub const ACC_INTERFACE: u16 = 0x0200;
pub const ACC_ABSTRACT: u16 = 0x0400;
pub const ACC_BRIDGE: u16 = 0x0040;
pub const ACC_SYNTHETIC: u16 = 0x1000;
pub const ACC_ANNOTATION: u16 = 0x2000;
pub const ACC_ENUM: u16 = 0x4000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompiledClass {
    pub source: String,
    pub method_count: usize,
    pub field_count: usize,
    pub fully_lifted_methods: usize,
    pub fallback_methods: usize,
    pub decode_error_count: usize,
}

struct FieldMetadata {
    name: String,
    ty: JavaType,
}

#[must_use]
pub fn class_access_keywords(flags: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        parts.push("public");
    }
    if flags & ACC_ABSTRACT != 0 && flags & ACC_INTERFACE == 0 {
        parts.push("abstract");
    }
    if flags & ACC_FINAL != 0 {
        parts.push("final");
    }
    parts.join(" ")
}

#[must_use]
pub fn member_access_keywords(flags: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & ACC_PUBLIC != 0 {
        parts.push("public");
    } else if flags & ACC_PRIVATE != 0 {
        parts.push("private");
    } else if flags & ACC_PROTECTED != 0 {
        parts.push("protected");
    }
    if flags & ACC_STATIC != 0 {
        parts.push("static");
    }
    if flags & ACC_FINAL != 0 {
        parts.push("final");
    }
    if flags & ACC_ABSTRACT != 0 {
        parts.push("abstract");
    }
    if flags & ACC_SYNCHRONIZED != 0 {
        parts.push("synchronized");
    }
    if flags & ACC_NATIVE != 0 {
        parts.push("native");
    }
    if flags & ACC_VOLATILE != 0 {
        parts.push("volatile");
    }
    if flags & ACC_TRANSIENT != 0 {
        parts.push("transient");
    }
    parts.join(" ")
}

#[must_use]
pub fn decompile_class(cf: &ClassFile) -> DecompiledClass {
    crate::name_disambig::ensure_writable_identifier_scope(
        declared_identifiers(std::iter::once(cf)),
        || decompile_class_scoped(cf),
    )
}

fn decompile_class_scoped(cf: &ClassFile) -> DecompiledClass {
    let mut source: String = String::with_capacity(2048);
    let raw_name: &str = match cf.this_class_name() {
        Ok(name) => name,
        Err(error) => {
            crate::debug::dbg_kv("class-metadata-reject", || error.to_string());
            return DecompiledClass {
                source: "public class UnknownClass {\n    // <decompile: malformed bytecode>\n}\n"
                    .to_owned(),
                method_count: cf.methods.len(),
                field_count: cf.fields.len(),
                fully_lifted_methods: 0,
                fallback_methods: cf.methods.len(),
                decode_error_count: 1,
            };
        }
    };
    let this_name: String = crate::name_disambig::rewrite_active(raw_name);
    let simple_raw: &str = this_name.rsplit('/').next().unwrap_or(&this_name);
    let simple_writable: String = descriptor::java_writable_identifier(simple_raw);
    let simple: &str = &simple_writable;
    let package: Option<&str> = this_name.rfind('/').map(|p| &this_name[..p]);

    if let Some(pkg) = package {
        let _ = writeln!(source, "package {};", pkg.replace('/', "."));
        let _ = writeln!(source);
    }

    let mut annotation_renderer: crate::attributes::DeclarationAnnotationRenderer =
        crate::attributes::DeclarationAnnotationRenderer::new(cf);
    source.push_str(&annotation_renderer.render(cf, &cf.attributes, ""));
    let structure: crate::attributes::ClassStructure = crate::attributes::analyze(cf);
    let generic_class: Option<crate::signature::RecoveredClassSignature> =
        crate::signature::recover_class(cf);
    let is_interface: bool = cf.access_flags & ACC_INTERFACE != 0;
    let is_annotation: bool = cf.access_flags & ACC_ANNOTATION != 0;
    let is_enum: bool = cf.access_flags & ACC_ENUM != 0;
    let class_flags: u16 = if is_enum {
        cf.access_flags & !(ACC_FINAL | ACC_ABSTRACT)
    } else {
        cf.access_flags
    };
    let kw: String = class_access_keywords(class_flags);
    let kind: &str = if is_annotation {
        "@interface"
    } else if is_interface {
        "interface"
    } else if is_enum {
        "enum"
    } else if structure.is_record {
        "record"
    } else {
        "class"
    };
    let sealed_kw: &str = if structure.is_sealed && !is_enum {
        "sealed "
    } else {
        ""
    };
    if kw.is_empty() {
        let _ = write!(source, "{sealed_kw}{kind} {simple}");
    } else {
        let _ = write!(source, "{kw} {sealed_kw}{kind} {simple}");
    }
    if let Some(signature) = &generic_class {
        source.push_str(&signature.type_parameters);
    }
    if structure.is_record {
        let components: Vec<String> = structure
            .record_components
            .iter()
            .filter_map(|c| {
                let field: Option<&FieldInfo> = cf.fields.iter().find(|field: &&FieldInfo| {
                    cf.utf8_at(field.name_index)
                        .is_ok_and(|name: &str| name == c.name)
                });
                let ty: String = field
                    .and_then(|value: &FieldInfo| {
                        crate::signature::recover_field(cf, value, generic_class.as_ref())
                    })
                    .or_else(|| descriptor::parse_field(&c.descriptor).map(|t| t.render()))?;
                Some(format!("{ty} {}", c.name))
            })
            .collect();
        let _ = write!(source, "({})", components.join(", "));
    }

    let super_name: Option<String> = if cf.super_class == 0 {
        None
    } else {
        cf.class_name(cf.super_class).ok().map(str::to_string)
    };
    if let Some(sup) = &super_name
        && sup != "java/lang/Object"
        && !is_interface
        && !is_enum
    {
        let rendered_superclass: String = generic_class.as_ref().map_or_else(
            || descriptor::binary_to_source(sup),
            |signature: &crate::signature::RecoveredClassSignature| signature.superclass.clone(),
        );
        let _ = write!(source, " extends {rendered_superclass}");
    }
    if !is_annotation && !cf.interfaces.is_empty() {
        let names: Vec<String> = generic_class.as_ref().map_or_else(
            || {
                cf.interfaces
                    .iter()
                    .filter_map(|&i| cf.class_name(i).ok().map(descriptor::binary_to_source))
                    .collect()
            },
            |signature: &crate::signature::RecoveredClassSignature| signature.interfaces.clone(),
        );
        if !names.is_empty() {
            let verb: &str = if is_interface {
                "extends"
            } else {
                "implements"
            };
            let _ = write!(source, " {verb} {}", names.join(", "));
        }
    }
    if structure.is_sealed && !is_enum && !structure.permitted_subclasses.is_empty() {
        let permitted: Vec<String> = structure
            .permitted_subclasses
            .iter()
            .map(|s| descriptor::binary_to_source(s))
            .collect();
        let _ = write!(source, " permits {}", permitted.join(", "));
    }
    let _ = writeln!(source, " {{");

    let field_metadata: Vec<Result<FieldMetadata>> = cf
        .fields
        .iter()
        .map(|field: &FieldInfo| decode_field_metadata(cf, field))
        .collect();
    let mut decode_error_count: usize = field_metadata
        .iter()
        .filter(|metadata: &&Result<FieldMetadata>| metadata.is_err())
        .count();
    let mut field_count: usize = 0;
    if is_enum {
        let enum_metadata_complete: bool =
            cf.fields
                .iter()
                .enumerate()
                .all(|(index, field): (usize, &FieldInfo)| {
                    field.access_flags & ACC_ENUM == 0 || field_metadata[index].is_ok()
                });
        if enum_metadata_complete && enum_constants_recoverable(cf, &structure) {
            let enum_fields: Vec<(usize, &FieldInfo)> = cf
                .fields
                .iter()
                .enumerate()
                .filter(|(_, field): &(usize, &FieldInfo)| field.access_flags & ACC_ENUM != 0)
                .collect();
            for (ordinal, (field_index, field)) in enum_fields.iter().enumerate() {
                let metadata: &FieldMetadata = match &field_metadata[*field_index] {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                source.push_str(&render_member_annotations(
                    &mut annotation_renderer,
                    cf,
                    &field.attributes,
                    "    ",
                ));
                let separator: char = if ordinal + 1 == enum_fields.len() {
                    ';'
                } else {
                    ','
                };
                let _ = writeln!(source, "    {}{separator}", metadata.name);
                field_count += 1;
            }
            if enum_fields.is_empty() {
                let _ = writeln!(source, "    ;");
            }
        } else {
            let _ = writeln!(source, "    /* unresolved enum constants */");
            let _ = writeln!(source, "    ;");
        }
    }
    for (field_index, field) in cf.fields.iter().enumerate() {
        let metadata: &FieldMetadata = match &field_metadata[field_index] {
            Ok(metadata) => metadata,
            Err(error) => {
                crate::debug::dbg_kv("field-metadata-reject", || error.to_string());
                let _ = writeln!(source, "    // <decompile: malformed field metadata>");
                field_count += 1;
                continue;
            }
        };
        if is_enum && (field.access_flags & ACC_ENUM != 0 || metadata.name == "$VALUES") {
            continue;
        }
        if let Some(line_value) = render_field(cf, field, metadata, generic_class.as_ref()) {
            let line: String = line_value;
            source.push_str(&render_member_annotations(
                &mut annotation_renderer,
                cf,
                &field.attributes,
                "    ",
            ));
            let _ = writeln!(source, "    {line}");
            field_count += 1;
        }
    }
    if field_count > 0 {
        let _ = writeln!(source);
    }

    let mut method_count: usize = 0;
    let mut fully_lifted: usize = 0;
    let mut fallback: usize = 0;
    let annotation_defaults: BTreeMap<usize, String> = if is_annotation {
        crate::attributes::render_annotation_defaults(cf)
    } else {
        BTreeMap::new()
    };
    for (method_index, method) in cf.methods.iter().enumerate() {
        if is_bridge_method(method) {
            continue;
        }
        if is_enum && is_generated_enum_method(cf, method) {
            if cf
                .utf8_at(method.name_index)
                .is_ok_and(|name: &str| name == "<clinit>")
            {
                let annotations: String = render_member_annotations(
                    &mut annotation_renderer,
                    cf,
                    &method.attributes,
                    "    ",
                );
                if !annotations.is_empty() {
                    source.push_str("    /* unresolved static initializer annotations */\n");
                }
            }
            continue;
        }
        let rendered: RenderedMethod = render_method(
            cf,
            method,
            simple,
            is_interface,
            annotation_defaults.get(&method_index).map(String::as_str),
            generic_class.as_ref(),
        );
        let rendered_annotations: String =
            render_member_annotations(&mut annotation_renderer, cf, &method.attributes, "    ");
        if cf
            .utf8_at(method.name_index)
            .is_ok_and(|name: &str| name == "<clinit>")
            && !rendered_annotations.is_empty()
        {
            source.push_str("    /* unresolved static initializer annotations */\n");
        } else {
            source.push_str(&rendered_annotations);
        }
        let _ = writeln!(source, "{}", rendered.text);
        method_count += 1;
        if rendered.fully_lifted {
            fully_lifted += 1;
        } else if rendered.has_body || rendered.refused {
            fallback += 1;
        }
        if rendered.refused {
            decode_error_count += 1;
        }
    }

    let _ = writeln!(source, "}}");

    DecompiledClass {
        source,
        method_count,
        field_count,
        fully_lifted_methods: fully_lifted,
        fallback_methods: fallback,
        decode_error_count,
    }
}

fn render_member_annotations(
    renderer: &mut crate::attributes::DeclarationAnnotationRenderer,
    cf: &ClassFile,
    attributes: &[crate::classfile::Attribute],
    indent: &str,
) -> String {
    renderer.render(cf, attributes, indent)
}

fn decode_field_metadata(cf: &ClassFile, field: &FieldInfo) -> Result<FieldMetadata> {
    let name: String = cf.utf8_at(field.name_index)?.to_owned();
    let descriptor: &str = cf.utf8_at(field.descriptor_index)?;
    let ty: JavaType = descriptor::parse_field(descriptor).ok_or_else(|| Error::BadBytecode {
        offset: usize::from(field.descriptor_index),
        reason: "field descriptor is invalid",
    })?;
    Ok(FieldMetadata { name, ty })
}

fn is_assertions_disabled_field(field: &FieldInfo, metadata: &FieldMetadata) -> bool {
    field.access_flags & (ACC_STATIC | ACC_FINAL | ACC_SYNTHETIC)
        == (ACC_STATIC | ACC_FINAL | ACC_SYNTHETIC)
        && metadata.name == "$assertionsDisabled"
        && matches!(metadata.ty, JavaType::Boolean)
}

fn render_field(
    cf: &ClassFile,
    field: &FieldInfo,
    metadata: &FieldMetadata,
    class_signature: Option<&crate::signature::RecoveredClassSignature>,
) -> Option<String> {
    if is_assertions_disabled_field(field, metadata) {
        return None;
    }
    let rendered_type: String = crate::signature::recover_field(cf, field, class_signature)
        .unwrap_or_else(|| metadata.ty.render());
    let kw: String = member_access_keywords(field.access_flags);
    let constant: Option<String> = constant_value_initializer(cf, field, &metadata.ty);
    let prefix: String = if kw.is_empty() {
        String::new()
    } else {
        format!("{kw} ")
    };
    match constant {
        Some(value) => Some(format!(
            "{prefix}{rendered_type} {} = {value};",
            metadata.name
        )),
        None => Some(format!("{prefix}{rendered_type} {};", metadata.name)),
    }
}

fn constant_value_index(cf: &ClassFile, field: &FieldInfo) -> Option<u16> {
    let mut index: Option<u16> = None;
    for attr in &field.attributes {
        if !cf
            .utf8_at(attr.name_index)
            .is_ok_and(|name: &str| name == "ConstantValue")
        {
            continue;
        }
        if index.is_some() || attr.info.len() != 2 {
            return None;
        }
        index = Some(u16::from_be_bytes([attr.info[0], attr.info[1]]));
    }
    index
}

fn constant_value_initializer(cf: &ClassFile, field: &FieldInfo, ty: &JavaType) -> Option<String> {
    if field.access_flags & ACC_STATIC == 0 {
        return None;
    }
    let index: u16 = constant_value_index(cf, field)?;
    let entry: &ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    match (ty, entry) {
        (JavaType::Boolean, ConstantPoolEntry::Integer(value)) => match value {
            0 => Some("false".to_string()),
            1 => Some("true".to_string()),
            _ => None,
        },
        (JavaType::Byte, ConstantPoolEntry::Integer(value)) if i8::try_from(*value).is_ok() => {
            Some(value.to_string())
        }
        (JavaType::Short, ConstantPoolEntry::Integer(value)) if i16::try_from(*value).is_ok() => {
            Some(value.to_string())
        }
        (JavaType::Char, ConstantPoolEntry::Integer(value)) if u16::try_from(*value).is_ok() => {
            Some(value.to_string())
        }
        (JavaType::Int, ConstantPoolEntry::Integer(value)) => Some(value.to_string()),
        (JavaType::Long, ConstantPoolEntry::Long(_))
        | (JavaType::Float, ConstantPoolEntry::Float(_))
        | (JavaType::Double, ConstantPoolEntry::Double(_)) => bytecode::resolve_ref(cf, index),
        (JavaType::Object(name), ConstantPoolEntry::String { .. })
            if name == "Ljava/lang/String;" =>
        {
            bytecode::resolve_ref(cf, index)
        }
        _ => None,
    }
}

fn enum_constants_recoverable(
    cf: &ClassFile,
    structure: &crate::attributes::ClassStructure,
) -> bool {
    if structure.is_sealed {
        return reject_enum_constants(cf, "permitted subclasses require constant bodies");
    }
    match crate::attributes::parse_inner_classes(cf) {
        crate::attributes::InnerClassesAttribute::Rejected => {
            return reject_enum_constants(cf, "invalid inner class metadata");
        }
        crate::attributes::InnerClassesAttribute::Absent
        | crate::attributes::InnerClassesAttribute::Parsed(_) => {}
    }
    let enum_fields: Vec<&FieldInfo> = cf
        .fields
        .iter()
        .filter(|field: &&FieldInfo| field.access_flags & ACC_ENUM != 0)
        .collect();
    let mut names: BTreeSet<&str> = BTreeSet::new();
    if enum_fields.iter().any(|field: &&FieldInfo| {
        !cf.utf8_at(field.name_index).is_ok_and(|name: &str| {
            crate::name_disambig::is_java_type_identifier(name) && names.insert(name)
        })
    }) {
        return reject_enum_constants(cf, "constant names are not distinct Java identifiers");
    }
    if cf.fields.iter().any(|field: &FieldInfo| {
        field.access_flags & ACC_ENUM == 0
            && !cf
                .utf8_at(field.name_index)
                .is_ok_and(|name: &str| name == "$VALUES")
            && constant_value_index(cf, field).is_none()
    }) {
        return reject_enum_constants(cf, "field initialization is not source-representable");
    }
    let constructors: Vec<&MethodInfo> = cf
        .methods
        .iter()
        .filter(|method: &&MethodInfo| {
            cf.utf8_at(method.name_index)
                .is_ok_and(|name: &str| name == "<init>")
        })
        .collect();
    if constructors.len() != 1 {
        return reject_enum_constants(cf, "constructor count is not one");
    }
    if !enum_constructor_is_implicit(cf, constructors[0]) {
        return reject_enum_constants(cf, "constructor has source-only parameters or effects");
    }
    if enum_clinit_has_user_effects(cf) {
        return reject_enum_constants(cf, "static initialization has source-only effects");
    }
    true
}

fn reject_enum_constants(cf: &ClassFile, reason: &'static str) -> bool {
    crate::debug::dbg_kv("enum-constant-reject", || {
        format!("{}: {reason}", cf.this_class_name().unwrap_or("<unknown>"))
    });
    false
}

fn enum_degradation_marker_name(cf: &ClassFile) -> String {
    let taken: BTreeSet<&str> = cf
        .fields
        .iter()
        .filter_map(|field: &FieldInfo| cf.utf8_at(field.name_index).ok())
        .collect();
    let base: &str = "disrobe_unresolved_enum_constants";
    if !taken.contains(base) {
        return base.to_string();
    }
    for suffix in 2..=taken.len().saturating_add(2) {
        let candidate: String = format!("{base}_{suffix}");
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
    }
    format!("{base}_fallback")
}

fn enum_constructor_is_implicit(cf: &ClassFile, constructor: &MethodInfo) -> bool {
    let descriptor_ok: bool = cf
        .utf8_at(constructor.descriptor_index)
        .ok()
        .and_then(descriptor::parse_method)
        .is_some_and(|descriptor: MethodDescriptor| {
            descriptor.params
                == vec![
                    JavaType::Object("Ljava/lang/String;".to_string()),
                    JavaType::Int,
                ]
                && descriptor.returns == JavaType::Void
        });
    if !descriptor_ok {
        crate::debug::dbg_kv("enum-constructor-reject", || {
            "descriptor is not (String, int) to void".to_string()
        });
        return false;
    }
    let MethodCode::Decoded(code): MethodCode = find_code(cf, constructor) else {
        crate::debug::dbg_kv("enum-constructor-reject", || "Code is absent".to_string());
        return false;
    };
    let Ok(instructions): Result<Vec<Instruction>> = disassemble(&code.code) else {
        crate::debug::dbg_kv("enum-constructor-reject", || {
            "Code does not disassemble".to_string()
        });
        return false;
    };
    if instructions.len() != 5
        || instructions[0].opcode != 0x2A
        || instructions[1].opcode != 0x2B
        || instructions[2].opcode != 0x1C
        || instructions[3].opcode != 0xB7
        || instructions[4].opcode != 0xB1
    {
        crate::debug::dbg_kv("enum-constructor-reject", || {
            instructions
                .iter()
                .map(|instruction: &Instruction| format!("{:02x}", instruction.opcode))
                .collect::<Vec<String>>()
                .join(" ")
        });
        return false;
    }
    let Operands::ConstPool(index) = &instructions[3].operands else {
        return false;
    };
    matches!(
        cf.constant_pool.get(usize::from(*index)),
        Some(ConstantPoolEntry::Methodref { .. })
    ) && bytecode::resolve_ref(cf, *index).as_deref()
        == Some("java/lang/Enum.<init>:(Ljava/lang/String;I)V")
}

fn is_generated_enum_method(cf: &ClassFile, method: &MethodInfo) -> bool {
    let Ok(name): core::result::Result<&str, _> = cf.utf8_at(method.name_index) else {
        return false;
    };
    if name == "<init>" || name == "<clinit>" {
        return true;
    }
    let Ok(descriptor): core::result::Result<&str, _> = cf.utf8_at(method.descriptor_index) else {
        return false;
    };
    let Ok(class_name): core::result::Result<&str, _> = cf.this_class_name() else {
        return false;
    };
    match name {
        "values" => descriptor == format!("()[L{class_name};"),
        "valueOf" => descriptor == format!("(Ljava/lang/String;)L{class_name};"),
        _ => false,
    }
}

fn enum_clinit_has_user_effects(cf: &ClassFile) -> bool {
    let Some(clinit): Option<&MethodInfo> = cf.methods.iter().find(|method: &&MethodInfo| {
        cf.utf8_at(method.name_index)
            .is_ok_and(|name: &str| name == "<clinit>")
    }) else {
        return true;
    };
    let MethodCode::Decoded(code): MethodCode = find_code(cf, clinit) else {
        return true;
    };
    let Ok(instructions): Result<Vec<Instruction>> = disassemble(&code.code) else {
        return true;
    };
    let Ok(class_name): core::result::Result<&str, _> = cf.this_class_name() else {
        return true;
    };
    let constructor: String = format!("{class_name}.<init>:(Ljava/lang/String;I)V");
    let values: String = format!("{class_name}.$values:()[L{class_name};");
    let mut generated_fields: BTreeSet<String> = cf
        .fields
        .iter()
        .filter(|field: &&FieldInfo| field.access_flags & ACC_ENUM != 0)
        .filter_map(|field: &FieldInfo| {
            let name: &str = cf.utf8_at(field.name_index).ok()?;
            Some(format!("{class_name}.{name}:L{class_name};"))
        })
        .collect();
    generated_fields.insert(format!("{class_name}.$VALUES:[L{class_name};"));
    for instruction in &instructions {
        let accepted: bool = match instruction.opcode {
            0x02..=0x08 | 0x10 | 0x11 | 0x12 | 0x13 | 0x59 | 0xB1 => true,
            0xBB => match &instruction.operands {
                Operands::ConstPool(index) => {
                    bytecode::resolve_ref(cf, *index).as_deref() == Some(class_name)
                }
                _ => false,
            },
            0xB7 => match &instruction.operands {
                Operands::ConstPool(index) => {
                    bytecode::resolve_ref(cf, *index).as_deref() == Some(constructor.as_str())
                }
                _ => false,
            },
            0xB3 => match &instruction.operands {
                Operands::ConstPool(index) => bytecode::resolve_ref(cf, *index)
                    .is_some_and(|reference: String| generated_fields.contains(&reference)),
                _ => false,
            },
            0xB8 => match &instruction.operands {
                Operands::ConstPool(index) => {
                    bytecode::resolve_ref(cf, *index).as_deref() == Some(values.as_str())
                }
                _ => false,
            },
            _ => false,
        };
        if !accepted {
            return true;
        }
    }
    false
}

struct RenderedMethod {
    text: String,
    fully_lifted: bool,
    has_body: bool,
    refused: bool,
}

const RECOMPILE_SAFE_LAMBDA_PREFIX: &str = "synthLambda$";

fn recompile_safe_method_name(name: &str) -> String {
    let delambdad: String = name.strip_prefix("lambda$").map_or_else(
        || name.to_string(),
        |rest: &str| format!("{RECOMPILE_SAFE_LAMBDA_PREFIX}{rest}"),
    );
    descriptor::java_writable_identifier(&delambdad)
}

fn refused_metadata_signature(name: &str, class_simple: &str) -> String {
    if name == "<init>" {
        format!("    {class_simple}()")
    } else if name == "<clinit>" {
        "    static".to_owned()
    } else {
        format!("    void {}()", recompile_safe_method_name(name))
    }
}

fn render_method(
    cf: &ClassFile,
    method: &MethodInfo,
    class_simple: &str,
    is_interface: bool,
    annotation_default: Option<&str>,
    class_signature: Option<&crate::signature::RecoveredClassSignature>,
) -> RenderedMethod {
    render_method_mode(
        cf,
        method,
        class_simple,
        is_interface,
        annotation_default,
        class_signature,
        true,
    )
}

fn render_method_mode(
    cf: &ClassFile,
    method: &MethodInfo,
    class_simple: &str,
    is_interface: bool,
    annotation_default: Option<&str>,
    class_signature: Option<&crate::signature::RecoveredClassSignature>,
    allow_generic_signature: bool,
) -> RenderedMethod {
    let name: &str = match cf.utf8_at(method.name_index) {
        Ok(name) => name,
        Err(error) => {
            let fallback_name: String = format!("malformedMethod{}", method.name_index);
            let signature: String = format!("    void {fallback_name}()");
            let reason: String = format!("method name: {error}");
            return render_refused_method(signature, cf, &fallback_name, &reason);
        }
    };
    let desc: &str = match cf.utf8_at(method.descriptor_index) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            let signature: String = refused_metadata_signature(name, class_simple);
            let reason: String = format!("method descriptor: {error}");
            return render_refused_method(signature, cf, name, &reason);
        }
    };
    let Some(parsed_method): Option<MethodDescriptor> = descriptor::parse_method(desc) else {
        let signature: String = refused_metadata_signature(name, class_simple);
        return render_refused_method(signature, cf, name, "invalid method descriptor");
    };
    let parsed: Option<MethodDescriptor> = Some(parsed_method);
    let method_code: MethodCode = find_code(cf, method);
    let generic_signature: Option<crate::signature::RecoveredMethodSignature> =
        allow_generic_signature
            .then(|| crate::signature::recover_method(cf, method, class_signature))
            .flatten();
    let method_flags: u16 = method.access_flags & !(ACC_VOLATILE | ACC_TRANSIENT);
    let mut kw: String = member_access_keywords(method_flags);
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let is_varargs: bool = method.access_flags & ACC_VARARGS != 0;
    let is_bodyless: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) != 0;
    let is_private: bool = method.access_flags & ACC_PRIVATE != 0;
    let needs_default: bool =
        is_interface && !is_bodyless && !is_static && !is_private && name != "<clinit>";
    if needs_default {
        kw = if kw.is_empty() {
            "default".to_string()
        } else {
            format!("{kw} default")
        };
    }

    let mut signature: String = String::new();
    if kw.is_empty() {
        let _ = write!(signature, "    ");
    } else {
        let _ = write!(signature, "    {kw} ");
    }

    let mut local_index: u16 = u16::from(!is_static);
    let mut param_names: Vec<(u16, String)> = Vec::new();
    let mut param_types: BTreeMap<u16, String> = BTreeMap::new();
    let mut boolean_params: BTreeSet<String> = BTreeSet::new();
    let params: String = match &parsed {
        Some(md) => {
            let mut rendered: Vec<String> = Vec::with_capacity(md.params.len());
            for (i, p) in md.params.iter().enumerate() {
                let pname: String = format!("arg{i}");
                let ty: String = generic_signature.as_ref().map_or_else(
                    || render_parameter_type(p, is_varargs && i + 1 == md.params.len()),
                    |signature: &crate::signature::RecoveredMethodSignature| {
                        render_generic_parameter_type(
                            &signature.parameters[i],
                            is_varargs && i + 1 == md.params.len(),
                        )
                    },
                );
                rendered.push(format!("{ty} {pname}"));
                if matches!(p, JavaType::Boolean) {
                    boolean_params.insert(pname.clone());
                }
                if matches!(p, JavaType::Array(_)) {
                    param_types.insert(
                        local_index,
                        ty.trim_end_matches("...").to_string()
                            + if is_varargs && i + 1 == md.params.len() {
                                "[]"
                            } else {
                                ""
                            },
                    );
                } else if matches!(p, JavaType::Object(_))
                    && let Some(signature) = &generic_signature
                {
                    param_types.insert(local_index, signature.parameters[i].clone());
                }
                param_names.push((local_index, pname));
                local_index += if p.category_two() { 2 } else { 1 };
            }
            rendered.join(", ")
        }
        None => String::new(),
    };

    let throws_clause: String = if name == "<clinit>" {
        String::new()
    } else if let Some(signature) = &generic_signature
        && !signature.throws.is_empty()
    {
        format!(" throws {}", signature.throws.join(", "))
    } else {
        method_throws_clause(cf, method)
    };
    let generic_prefix: String = generic_signature
        .as_ref()
        .map_or_else(String::new, |signature| {
            if signature.type_parameters.is_empty() {
                String::new()
            } else {
                format!("{} ", signature.type_parameters)
            }
        });
    if name == "<init>" {
        let _: std::fmt::Result = write!(
            signature,
            "{generic_prefix}{class_simple}({params}){throws_clause}"
        );
    } else if name == "<clinit>" {
        signature = "    static".to_string();
    } else {
        let ret: String = generic_signature.as_ref().map_or_else(
            || {
                parsed
                    .as_ref()
                    .map_or_else(|| "void".to_string(), |md| md.returns.render())
            },
            |generic: &crate::signature::RecoveredMethodSignature| generic.result.clone(),
        );
        let emit_name: String = recompile_safe_method_name(name);
        let _: std::fmt::Result = write!(
            signature,
            "{generic_prefix}{ret} {emit_name}({params}){throws_clause}"
        );
    }

    let _: Option<()> = annotation_default.map(|value: &str| {
        let _: std::fmt::Result = if crate::attributes::is_unresolved_annotation_value(value) {
            write!(signature, " /* unresolved default value */")
        } else {
            write!(signature, " default {value}")
        };
    });
    if annotation_default.is_some() || is_bodyless {
        return match method_code {
            MethodCode::Absent => RenderedMethod {
                text: format!("{signature};"),
                fully_lifted: false,
                has_body: false,
                refused: false,
            },
            MethodCode::Decoded(_) => render_refused_declaration(
                signature,
                cf,
                name,
                "Code is present on a bodyless declaration",
            ),
            MethodCode::Refused(error) => {
                let reason: String = error.to_string();
                render_refused_declaration(signature, cf, name, &reason)
            }
        };
    }
    let code: CodeAttribute = match method_code {
        MethodCode::Decoded(code) => code,
        MethodCode::Absent => {
            return render_refused_method(signature, cf, name, "Code is absent");
        }
        MethodCode::Refused(error) => {
            let reason: String = error.to_string();
            return render_refused_method(signature, cf, name, &reason);
        }
    };

    let has_this: bool = !is_static && name != "<clinit>";
    let bool_return: bool = parsed
        .as_ref()
        .is_some_and(|md: &MethodDescriptor| matches!(md.returns, JavaType::Boolean));
    let body: MethodBody = match lift_method_body(
        cf,
        &code,
        &param_names,
        &param_types,
        &boolean_params,
        has_this,
        bool_return,
    ) {
        Ok(body) => body,
        Err(Error::UnrecoveredRegion { reason }) => {
            return render_unrecovered_method(signature, cf, name, reason);
        }
        Err(error) => {
            let reason: String = error.to_string();
            return render_refused_method(signature, cf, name, &reason);
        }
    };
    let stackmap_note: String =
        stackmap_resilience_note(cf, method, &code, parsed.as_ref(), is_static, name);
    let mut body_text: String = if name == "<clinit>" {
        strip_clinit_returns(&body.text)
    } else {
        body.text
    };
    if let Some(generic) = &generic_signature {
        let Some(adapted): Option<String> = adapt_generic_body(&body_text, generic) else {
            crate::debug::dbg_kv("generic-signature-reject", || {
                format!(
                    "{} method {name}: generic body adaptation exceeded its budget",
                    cf.this_class_name().unwrap_or("<unknown>")
                )
            });
            return render_method_mode(
                cf,
                method,
                class_simple,
                is_interface,
                annotation_default,
                class_signature,
                false,
            );
        };
        body_text = adapted;
    }
    if let Some(generic) = &generic_signature
        && !generic_body_source_compatible(&body_text, generic)
    {
        crate::debug::dbg_kv("generic-signature-reject", || {
            format!(
                "{} method {name}: recovered body is not type-compatible with the generic declaration",
                cf.this_class_name().unwrap_or("<unknown>")
            )
        });
        return render_method_mode(
            cf,
            method,
            class_simple,
            is_interface,
            annotation_default,
            class_signature,
            false,
        );
    }
    let mut text: String = signature;
    let _ = write!(text, " {{\n{stackmap_note}{body_text}    }}");
    RenderedMethod {
        text,
        fully_lifted: body.fully_lifted,
        has_body: true,
        refused: false,
    }
}

fn generic_body_source_compatible(
    body: &str,
    signature: &crate::signature::RecoveredMethodSignature,
) -> bool {
    if signature.type_parameter_names.is_empty() {
        return true;
    }
    if body.contains("((Object)") || has_uncast_next_call(body) {
        return false;
    }
    if !signature.type_parameter_names.contains(&signature.result) {
        return true;
    }
    body.lines()
        .filter_map(|line: &str| line.trim().strip_prefix("return "))
        .all(|expression: &str| {
            expression == "null;"
                || expression.starts_with("arg")
                || expression.starts_with(&format!("(({})", signature.result))
                || expression.starts_with(&format!("({})", signature.result))
        })
}

fn adapt_generic_body(
    body: &str,
    signature: &crate::signature::RecoveredMethodSignature,
) -> Option<String> {
    let mut aliases: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for (name, erasure) in &signature.type_parameter_erasures {
        aliases
            .entry(erasure)
            .and_modify(|current: &mut Option<&str>| *current = None)
            .or_insert(Some(name));
    }
    let mut replacements: BTreeMap<String, Option<String>> = BTreeMap::new();
    if let Some(result_erasure) = signature.type_parameter_erasures.get(&signature.result) {
        for line in body.lines() {
            let Some(expression): Option<&str> = line
                .trim()
                .strip_prefix("return ")
                .and_then(|value: &str| value.strip_suffix(';'))
            else {
                continue;
            };
            let Some(suffix): Option<&str> = expression.strip_prefix("var") else {
                continue;
            };
            if suffix.bytes().all(|byte: u8| byte.is_ascii_digit()) {
                insert_generic_replacement(
                    &mut replacements,
                    format!("(({result_erasure}) {expression})"),
                    format!("(({}) {expression})", signature.result),
                );
            }
        }
    }
    for (erasure, name) in aliases
        .iter()
        .filter_map(|(erasure, name)| name.map(|value: &str| (*erasure, value)))
    {
        insert_generic_replacement(
            &mut replacements,
            format!("(({erasure})"),
            format!("(({name})"),
        );
    }
    if let Some(Some(object_alias)) = aliases.get("Object") {
        for pattern in simple_next_call_patterns(body) {
            insert_generic_replacement(
                &mut replacements,
                pattern.clone(),
                format!("(({object_alias}) {pattern})"),
            );
        }
    }
    let active_replacements: BTreeMap<String, String> = replacements
        .into_iter()
        .filter_map(|(from, to): (String, Option<String>)| to.map(|value: String| (from, value)))
        .collect();
    let adapted: String = replace_java_code_many(body, &active_replacements)?;
    if !signature.type_parameter_names.contains(&signature.result) {
        return Some(adapted);
    }
    let mut out: String = String::with_capacity(adapted.len());
    for line in adapted.lines() {
        let trimmed: &str = line.trim();
        let Some(expression): Option<&str> = trimmed
            .strip_prefix("return ")
            .and_then(|value: &str| value.strip_suffix(';'))
        else {
            let _ = writeln!(out, "{line}");
            continue;
        };
        let already_typed: bool = expression == "null"
            || expression.starts_with("arg")
            || expression.starts_with(&format!("(({})", signature.result))
            || expression.starts_with(&format!("({})", signature.result));
        if already_typed {
            let _ = writeln!(out, "{line}");
            continue;
        }
        let indentation: &str = &line[..line.len().saturating_sub(line.trim_start().len())];
        let _ = writeln!(
            out,
            "{indentation}return (({}) ({expression}));",
            signature.result
        );
    }
    Some(out)
}

fn insert_generic_replacement(
    replacements: &mut BTreeMap<String, Option<String>>,
    from: String,
    to: String,
) {
    replacements
        .entry(from)
        .and_modify(|current: &mut Option<String>| {
            if current.as_ref() != Some(&to) {
                *current = None;
            }
        })
        .or_insert(Some(to));
}

fn simple_next_call_patterns(body: &str) -> BTreeSet<String> {
    let mut patterns: BTreeSet<String> = BTreeSet::new();
    for word in body.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '$' | '.'))
    }) {
        let Some(receiver): Option<&str> = word.strip_suffix(".next") else {
            continue;
        };
        if receiver.starts_with("var")
            && receiver[3..].bytes().all(|byte: u8| byte.is_ascii_digit())
        {
            patterns.insert(format!("{receiver}.next()"));
        }
    }
    patterns
}

fn has_uncast_next_call(body: &str) -> bool {
    body.lines().any(|line: &str| {
        line.contains(".next()") && !line.contains(") var") && !line.contains(") arg")
    })
}

fn replace_java_code(text: &str, from: &str, to: &str) -> String {
    let replacements: BTreeMap<String, String> =
        BTreeMap::from([(from.to_string(), to.to_string())]);
    match replace_java_code_many(text, &replacements) {
        Some(replaced) => replaced,
        None => text.to_string(),
    }
}

const MAX_GENERIC_REPLACEMENTS: usize = 4_096;
const MAX_GENERIC_REPLACEMENT_BYTES: usize = 262_144;

#[derive(Debug, Default)]
struct JavaReplacementNode {
    edges: BTreeMap<u8, usize>,
    replacement: Option<String>,
}

fn replacement_nodes(replacements: &BTreeMap<String, String>) -> Option<Vec<JavaReplacementNode>> {
    if replacements.len() > MAX_GENERIC_REPLACEMENTS
        || replacements
            .keys()
            .any(|pattern: &String| pattern.is_empty())
    {
        return None;
    }
    let total_bytes: usize =
        replacements
            .iter()
            .try_fold(0usize, |total: usize, (from, to): (&String, &String)| {
                total.checked_add(from.len())?.checked_add(to.len())
            })?;
    if total_bytes > MAX_GENERIC_REPLACEMENT_BYTES {
        return None;
    }
    let mut nodes: Vec<JavaReplacementNode> = vec![JavaReplacementNode::default()];
    nodes.try_reserve(total_bytes).ok()?;
    for (pattern, replacement) in replacements {
        let mut node_index: usize = 0;
        for byte in pattern.bytes() {
            let next_index: usize = if let Some(index) = nodes[node_index].edges.get(&byte) {
                *index
            } else {
                let index: usize = nodes.len();
                nodes.push(JavaReplacementNode::default());
                nodes[node_index].edges.insert(byte, index);
                index
            };
            node_index = next_index;
        }
        nodes[node_index].replacement = Some(replacement.clone());
    }
    Some(nodes)
}

fn longest_java_replacement<'a>(
    text: &'a str,
    start: usize,
    nodes: &'a [JavaReplacementNode],
) -> Option<(usize, &'a str)> {
    let mut node_index: usize = 0;
    let mut position: usize = start;
    let mut found: Option<(usize, &str)> = None;
    while let Some(byte) = text.as_bytes().get(position) {
        let Some(next_index): Option<&usize> = nodes[node_index].edges.get(byte) else {
            break;
        };
        node_index = *next_index;
        position = position.checked_add(1)?;
        if let Some(replacement) = nodes[node_index].replacement.as_deref() {
            found = Some((position, replacement));
        }
    }
    found
}

fn replace_java_code_many(text: &str, replacements: &BTreeMap<String, String>) -> Option<String> {
    if text.len() > MAX_RENDER_BYTES {
        return None;
    }
    if replacements.is_empty() {
        let mut copied: String = String::new();
        copied.try_reserve(text.len()).ok()?;
        copied.push_str(text);
        return Some(copied);
    }
    let nodes: Vec<JavaReplacementNode> = replacement_nodes(replacements)?;
    let mut out: String = String::new();
    out.try_reserve(text.len()).ok()?;
    let mut index: usize = 0;
    let mut mode: u8 = 0;
    let mut escaped: bool = false;
    while index < text.len() {
        let rest: &str = &text[index..];
        if mode == 0 {
            let replacement: Option<(usize, &str)> = longest_java_replacement(text, index, &nodes);
            if let Some((end, value)) = replacement {
                append_java_replacement(&mut out, value)?;
                index = end;
                continue;
            }
        }
        let Some(character): Option<char> = rest.chars().next() else {
            break;
        };
        let width: usize = character.len_utf8();
        if mode == 0 {
            if rest.starts_with("//") {
                mode = 3;
            } else if rest.starts_with("/*") {
                mode = 4;
            } else if character == '"' {
                mode = 1;
                escaped = false;
            } else if character == '\'' {
                mode = 2;
                escaped = false;
            }
        } else if mode == 1 || mode == 2 {
            let closing: char = if mode == 1 { '"' } else { '\'' };
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == closing {
                mode = 0;
            }
        } else if mode == 3 && character == '\n' {
            mode = 0;
        } else if mode == 4 && rest.starts_with("*/") {
            append_java_replacement(&mut out, "*/")?;
            index += 2;
            mode = 0;
            continue;
        }
        let mut encoded: [u8; 4] = [0; 4];
        append_java_replacement(&mut out, character.encode_utf8(&mut encoded))?;
        index += width;
    }
    Some(out)
}

fn append_java_replacement(out: &mut String, value: &str) -> Option<()> {
    let next_length: usize = out.len().checked_add(value.len())?;
    if next_length > MAX_RENDER_BYTES {
        return None;
    }
    let available: usize = out.capacity().saturating_sub(out.len());
    if available < value.len() {
        out.try_reserve(value.len() - available).ok()?;
    }
    out.push_str(value);
    Some(())
}

fn render_parameter_type(ty: &JavaType, is_varargs: bool) -> String {
    if is_varargs && let JavaType::Array(element) = ty {
        return format!("{}...", element.render());
    }
    ty.render()
}

fn render_generic_parameter_type(ty: &str, is_varargs: bool) -> String {
    if is_varargs && let Some(element) = ty.strip_suffix("[]") {
        return format!("{element}...");
    }
    ty.to_string()
}

fn strip_clinit_returns(body: &str) -> String {
    let mut out: String = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if trimmed == "return;" {
            continue;
        }
        if trimmed.starts_with("$assertionsDisabled = ") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn stackmap_resilience_note(
    cf: &ClassFile,
    method: &MethodInfo,
    code: &CodeAttribute,
    descriptor: Option<&MethodDescriptor>,
    is_static: bool,
    name: &str,
) -> String {
    let Some(raw_info): Option<&[u8]> = raw_code_info(cf, method) else {
        return String::new();
    };
    let Ok(insns) = disassemble(&code.code) else {
        return String::new();
    };
    let insns: Vec<Instruction> = insns;
    let report: crate::stackmap::StackMapReport =
        crate::stackmap::analyze_stack_map(raw_info, code.code.len(), &insns, &|idx: u16| {
            cf.utf8_at(idx).ok().map(str::to_owned)
        });
    let mut note: String = if report.consistent {
        String::new()
    } else if report.present {
        format!(
            "        // StackMapTable inconsistent with control flow ({} missing, {} stray frame offset(s)); offsets recomputed from the control-flow graph\n",
            report.missing_offsets.len(),
            report.stray_offsets.len()
        )
    } else {
        format!(
            "        // StackMapTable absent; {} frame offset(s) recomputed from the control-flow graph\n",
            report.missing_offsets.len()
        )
    };
    if let Some(extra) = frame_inference_note(cf, code, &insns, descriptor, is_static, name) {
        note.push_str(&extra);
    }
    note
}

fn frame_inference_note(
    cf: &ClassFile,
    code: &CodeAttribute,
    insns: &[Instruction],
    descriptor: Option<&MethodDescriptor>,
    is_static: bool,
    name: &str,
) -> Option<String> {
    let descriptor: &MethodDescriptor = descriptor?;
    let this_class: String = cf.this_class_name().unwrap_or("?").to_owned();
    let cfg: crate::decompile_struct::Cfg =
        crate::decompile_struct::build_cfg(insns, code, |idx: u16| {
            crate::bytecode::class_internal_name_at(cf, idx)
        })
        .ok()?;
    let report: crate::frame_infer::FrameInferReport = crate::frame_infer::infer_frames(
        &cfg,
        insns,
        descriptor,
        is_static,
        name == "<init>",
        &this_class,
        &|idx: u16| crate::bytecode::field_descriptor_at(cf, idx),
        &|idx: u16| crate::bytecode::method_name_descriptor_at(cf, idx),
        &|idx: u16| crate::bytecode::class_internal_name_at(cf, idx),
        &|_| None,
    );
    match report.outcome {
        crate::frame_infer::FrameInferOutcome::Converged => None,
        crate::frame_infer::FrameInferOutcome::Diverged => Some(
            "        // abstract frame inference did not reach a fixed point; method control flow is irreducible or adversarial\n"
                .to_owned(),
        ),
        crate::frame_infer::FrameInferOutcome::UnmodeledOpcode
        | crate::frame_infer::FrameInferOutcome::StackUnderflow => {
            report.first_unmodeled.map(|(pc, mnemonic): (u32, String)| {
                format!(
                    "        // abstract frame inference incomplete at pc {pc} ({mnemonic}); {} of {} instructions type-modeled\n",
                    report.modeled_instructions, report.total_instructions
                )
            })
        }
    }
}

fn raw_code_info<'a>(cf: &'a ClassFile, method: &'a MethodInfo) -> Option<&'a [u8]> {
    for attr in &method.attributes {
        if cf.utf8_at(attr.name_index).ok()? == "Code" {
            return Some(&attr.info);
        }
    }
    None
}

const fn is_bridge_method(method: &MethodInfo) -> bool {
    method.access_flags & ACC_BRIDGE != 0 && method.access_flags & ACC_SYNTHETIC != 0
}

enum MethodCode {
    Absent,
    Decoded(CodeAttribute),
    Refused(Error),
}

fn find_code(cf: &ClassFile, method: &MethodInfo) -> MethodCode {
    let mut code: Option<CodeAttribute> = None;
    for attr in &method.attributes {
        let attribute_name: &str = match cf.utf8_at(attr.name_index) {
            Ok(name) => name,
            Err(error) => return MethodCode::Refused(error),
        };
        if attribute_name == "Code" {
            if code.is_some() {
                return MethodCode::Refused(Error::BadBytecode {
                    offset: 0,
                    reason: "duplicate Code attribute",
                });
            }
            let parsed: CodeAttribute = match parse_code_attribute(&attr.info) {
                Ok(parsed) => parsed,
                Err(error) => return MethodCode::Refused(error),
            };
            code = Some(parsed);
        }
    }
    code.map_or(MethodCode::Absent, MethodCode::Decoded)
}

fn render_refused_method(
    mut signature: String,
    cf: &ClassFile,
    name: &str,
    reason: &str,
) -> RenderedMethod {
    crate::debug::dbg_kv("method-code-reject", || {
        format!(
            "{} method {name}: {reason}",
            cf.this_class_name().unwrap_or("<unknown>")
        )
    });
    if name == "<clinit>" {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n    }}"
        );
    } else {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: malformed bytecode>\n        throw new UnsupportedOperationException(\"malformed bytecode\");\n    }}"
        );
    }
    RenderedMethod {
        text: signature,
        fully_lifted: false,
        has_body: true,
        refused: true,
    }
}

fn render_unrecovered_method(
    mut signature: String,
    cf: &ClassFile,
    name: &str,
    reason: &'static str,
) -> RenderedMethod {
    crate::debug::dbg_kv("method-region-unrecovered", || {
        format!(
            "{} method {name}: {reason}",
            cf.this_class_name().unwrap_or("<unknown>")
        )
    });
    if name == "<clinit>" {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: not recovered: {reason}>\n    }}"
        );
    } else {
        let _: std::fmt::Result = write!(
            signature,
            " {{\n        // <decompile: not recovered: {reason}>\n        throw new UnsupportedOperationException(\"region not recovered\");\n    }}"
        );
    }
    RenderedMethod {
        text: signature,
        fully_lifted: false,
        has_body: true,
        refused: true,
    }
}

fn render_refused_declaration(
    mut signature: String,
    cf: &ClassFile,
    name: &str,
    reason: &str,
) -> RenderedMethod {
    crate::debug::dbg_kv("method-code-reject", || {
        format!(
            "{} method {name}: {reason}",
            cf.this_class_name().unwrap_or("<unknown>")
        )
    });
    let _: std::fmt::Result = write!(signature, "; // <decompile: malformed bytecode>");
    RenderedMethod {
        text: signature,
        fully_lifted: false,
        has_body: false,
        refused: true,
    }
}

fn method_throws_clause(cf: &ClassFile, method: &MethodInfo) -> String {
    let Some(data): Option<&[u8]> = method.attributes.iter().find_map(|a| {
        cf.utf8_at(a.name_index)
            .ok()
            .filter(|&n: &&str| n == "Exceptions")
            .map(|_| a.info.as_slice())
    }) else {
        return String::new();
    };
    if data.len() < 2 {
        return String::new();
    }
    let count: usize = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut names: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = 2 + i * 2;
        if off + 2 > data.len() {
            break;
        }
        let cp_idx: u16 = u16::from_be_bytes([data[off], data[off + 1]]);
        if let Ok(binary) = cf.class_name(cp_idx) {
            names.push(descriptor::binary_to_source(binary));
        }
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" throws {}", names.join(", "))
    }
}

struct MethodBody {
    text: String,
    fully_lifted: bool,
}

#[derive(Clone)]
pub(crate) enum Expr {
    Const(String),
    Local(String),
    This,
    Field {
        receiver: Box<Self>,
        owner: String,
        name: String,
        boolean: bool,
    },
    StaticField {
        owner: String,
        name: String,
        boolean: bool,
    },
    Binary {
        op: &'static str,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Unary {
        op: &'static str,
        value: Box<Self>,
    },
    Cast {
        ty: String,
        value: Box<Self>,
    },
    InstanceOf {
        value: Box<Self>,
        ty: String,
    },
    Cmp {
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    ArrayLength(Box<Self>),
    ArrayLoad {
        array: Box<Self>,
        index: Box<Self>,
    },
    New(String),
    NewArray {
        ty: String,
        size: Box<Self>,
    },
    ArrayInit {
        ty: String,
        elements: Vec<Self>,
    },
    Invoke {
        receiver: Option<Box<Self>>,
        owner: String,
        method: String,
        args: Vec<Self>,
        returns_bool: bool,
    },
    Opaque(String),
}

fn int_literal_as_bool(c: &str) -> Option<&'static str> {
    match c {
        "0" => Some("false"),
        "1" => Some("true"),
        _ => None,
    }
}

const fn narrow_int_param_bounds(want: &JavaType) -> Option<(&'static str, i32, i32)> {
    match want {
        JavaType::Byte => Some(("byte", -128, 127)),
        JavaType::Short => Some(("short", -32768, 32767)),
        JavaType::Char => Some(("char", 0, 65535)),
        _ => None,
    }
}

fn coerce_arg(arg: Expr, want: &JavaType) -> Expr {
    if matches!(want, JavaType::Boolean)
        && let Expr::Const(c) = &arg
        && let Some(b) = int_literal_as_bool(c)
    {
        return Expr::Const(b.to_string());
    }
    if let Some((ty, lo, hi)) = narrow_int_param_bounds(want)
        && let Expr::Const(c) = &arg
        && let Some(value) = parse_int_literal(c)
        && value >= lo
        && value <= hi
    {
        return Expr::Cast {
            ty: ty.to_string(),
            value: Box::new(arg),
        };
    }
    if let JavaType::Object(internal) = want
        && internal != "java/lang/Object"
        && matches!(&arg, Expr::Local(name) if local_is_object_typed(name))
    {
        return Expr::Cast {
            ty: want.render(),
            value: Box::new(arg),
        };
    }
    arg
}

impl Expr {
    pub(crate) fn discarded_side_effect(&self) -> Option<String> {
        match self {
            Self::Invoke { .. } => Some(self.render()),
            Self::Cast { value, .. } => value.discarded_side_effect(),
            _ => None,
        }
    }

    fn is_boolean(&self) -> bool {
        match self {
            Self::InstanceOf { .. } => true,
            Self::Invoke { returns_bool, .. } => *returns_bool,
            Self::Cast { ty, .. } => ty == "boolean",
            Self::Field { boolean, .. } | Self::StaticField { boolean, .. } => *boolean,
            Self::Local(name) => local_is_boolean_typed(name),
            _ => false,
        }
    }

    pub(crate) fn render(&self) -> String {
        match self {
            Self::Opaque(s) if s == HOLE_TOKEN => HOLE_RENDER.to_string(),
            Self::Const(s) | Self::Local(s) | Self::Opaque(s) => s.clone(),
            Self::This => "this".to_string(),
            Self::Field {
                receiver,
                owner,
                name,
                ..
            } => render_field_access(receiver, owner, name),
            Self::StaticField { owner, name, .. } => {
                format!("{owner}.{}", descriptor::java_writable_identifier(name))
            }
            Self::Binary { op, lhs, rhs } => {
                format!("({} {op} {})", lhs.render(), rhs.render())
            }
            Self::Unary { op, value } => format!("({op}{})", value.render()),
            Self::Cast { ty, value } => format!("(({ty}) {})", value.render()),
            Self::InstanceOf { value, ty } => {
                format!("({} instanceof {ty})", value.render())
            }
            Self::Cmp { lhs, rhs } => {
                format!("Integer.compare({}, {})", lhs.render(), rhs.render())
            }
            Self::ArrayLength(arr) => format!("{}.length", arr.render()),
            Self::ArrayLoad { array, index } => {
                format!("{}[{}]", array.render(), index.render())
            }
            Self::New(ty) => format!("new {ty}()"),
            Self::NewArray { ty, size } => {
                let trimmed: &str = ty.trim_end();
                let base: &str = trimmed.trim_end_matches("[]").trim_end();
                let suffix: &str = &trimmed[base.len()..];
                format!("new {base}[{}]{suffix}", size.render())
            }
            Self::ArrayInit { ty, elements } => {
                let rendered: Vec<String> = elements.iter().map(Self::render).collect();
                format!("new {ty}[]{{{}}}", rendered.join(", "))
            }
            Self::Invoke {
                receiver,
                owner,
                method,
                args,
                ..
            } => {
                if receiver.is_none()
                    && method == "valueOf"
                    && (owner == "Boolean" || owner == "java.lang.Boolean")
                    && let [Self::Const(c)] = args.as_slice()
                    && let Some(b) = int_literal_as_bool(c)
                {
                    return format!("{owner}.valueOf({b})");
                }
                if receiver.is_none()
                    && method == "valueOf"
                    && let Some(narrow) = boxing_valueof_cast(owner)
                    && let [single] = args.as_slice()
                {
                    return format!("{owner}.valueOf(({narrow}) {})", single.render());
                }
                let rendered_args: Vec<String> = args.iter().map(Self::render).collect();
                let joined: String = rendered_args.join(", ");
                let call_name: String = descriptor::java_writable_identifier(method);
                match receiver {
                    Some(r) => format!("{}.{call_name}({joined})", r.render()),
                    None => format!("{owner}.{call_name}({joined})"),
                }
            }
        }
    }

    fn static_type(&self) -> Option<String> {
        match self {
            Self::Cast { ty, .. } => Some(ty.clone()),
            Self::New(ty) => Some(ty.clone()),
            Self::StaticField { .. } | Self::Field { .. } => None,
            Self::InstanceOf { .. } => Some("boolean".to_string()),
            Self::Invoke { returns_bool, .. } if *returns_bool => Some("boolean".to_string()),
            _ => None,
        }
    }
}

fn boxing_valueof_cast(owner: &str) -> Option<&'static str> {
    match owner {
        "Byte" | "java.lang.Byte" => Some("byte"),
        "Short" | "java.lang.Short" => Some("short"),
        "Character" | "java.lang.Character" => Some("char"),
        _ => None,
    }
}

const fn is_atomic_receiver(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Local(_)
            | Expr::This
            | Expr::Const(_)
            | Expr::Field { .. }
            | Expr::StaticField { .. }
            | Expr::Invoke { .. }
            | Expr::ArrayLoad { .. }
            | Expr::ArrayLength(_)
    )
}

fn render_field_access(receiver: &Expr, owner: &str, name: &str) -> String {
    let owner_src: String = descriptor::binary_to_source(owner);
    let field: String = descriptor::java_writable_identifier(name);
    if matches!(receiver, Expr::This) {
        return format!("this.{field}");
    }
    let receiver_type_known: bool = receiver
        .static_type()
        .is_some_and(|t: String| t == owner_src);
    if receiver_type_known {
        let rendered: String = receiver.render();
        if is_atomic_receiver(receiver) {
            return format!("{rendered}.{field}");
        }
        return format!("({rendered}).{field}");
    }
    format!("(({owner_src}) {}).{field}", receiver.render())
}

fn narrow_invoke_receiver(receiver: Expr, owner_src: &str, virtual_dispatch: bool) -> Expr {
    if !virtual_dispatch || matches!(receiver, Expr::This) || owner_src == "Object" {
        return receiver;
    }
    let needs_cast: bool = match receiver.static_type() {
        Some(t) => t == "Object",
        None => receiver_is_object_typed(&receiver),
    };
    if needs_cast || receiver_is_object_local(&receiver) {
        Expr::Cast {
            ty: owner_src.to_string(),
            value: Box::new(receiver),
        }
    } else {
        receiver
    }
}

const fn receiver_is_object_typed(receiver: &Expr) -> bool {
    matches!(receiver, Expr::ArrayLoad { .. })
}

fn receiver_is_object_local(receiver: &Expr) -> bool {
    matches!(receiver, Expr::Local(name) if local_is_object_typed(name))
}

fn lift_method_body(
    cf: &ClassFile,
    code: &CodeAttribute,
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    boolean_params: &BTreeSet<String>,
    has_this: bool,
    bool_return: bool,
) -> Result<MethodBody> {
    let raw_insns: Vec<Instruction> = validate_code_attribute(cf, code)?;
    let mut insns: Vec<Instruction> = if crate::jsr_inline::contains_jsr(&raw_insns) {
        let (inlined, report): (Vec<Instruction>, crate::jsr_inline::JsrInlineReport) =
            crate::jsr_inline::inline_jsr_subroutines(&raw_insns);
        if report.bailed { raw_insns } else { inlined }
    } else {
        raw_insns
    };
    let boolean_param_slots: BTreeSet<u16> = params
        .iter()
        .filter(|(_, name): &&(u16, String)| boolean_params.contains(name))
        .map(|(slot, _): &(u16, String)| *slot)
        .collect();
    let next_fresh: u16 = split_reused_boolean_parameter_ranges(
        cf,
        &mut insns,
        code.max_locals,
        &code.exception_table,
        &boolean_param_slots,
    );
    split_reused_primitive_ranges(&mut insns, next_fresh);
    if insns.is_empty() {
        return Ok(MethodBody {
            text: String::new(),
            fully_lifted: true,
        });
    }
    let bootstraps: Vec<crate::attributes::BootstrapMethod> =
        crate::attributes::analyze(cf).bootstrap_methods;
    let exc_regions: Vec<ExceptionRegion> = code
        .exception_table
        .iter()
        .map(|e: &crate::bytecode::ExceptionEntry| ExceptionRegion {
            try_start_pc: u32::from(e.start_pc),
            try_end_pc: u32::from(e.end_pc),
            handler_pc: u32::from(e.handler_pc),
            catch_type: if e.catch_type == 0 {
                None
            } else {
                cf.class_name(e.catch_type).ok().map(str::to_owned)
            },
        })
        .collect();
    if crate::debug::dbg_enabled() && !exc_regions.is_empty() {
        crate::debug::dbg_kv("exception-table", || {
            let catches: Vec<String> = exc_regions
                .iter()
                .map(|r: &ExceptionRegion| {
                    format!(
                        "[{:#x}..{:#x})->{:#x} {}",
                        r.try_start_pc,
                        r.try_end_pc,
                        r.handler_pc,
                        r.catch_type.as_deref().unwrap_or("any (finally)")
                    )
                })
                .collect();
            format!("{} region(s): {}", exc_regions.len(), catches.join(", "))
        });
    }
    let exc_conflicted: BTreeSet<u16> = exception_value_conflicted_slots(&insns, &exc_regions);
    let mut object_locals: BTreeSet<String> =
        object_typed_local_names(cf, &insns, params, &exc_conflicted);
    let source_slot_types: BTreeMap<u16, String> =
        compute_slot_types(cf, &insns, params, param_types, &exc_regions);
    for (slot, ty) in &source_slot_types {
        if ty != "Object" {
            object_locals.remove(&local_name(*slot, params));
        }
    }
    let param_slots: BTreeSet<u16> = params.iter().map(|(i, _): &(u16, String)| *i).collect();
    let mut boolean_locals: BTreeSet<String> = boolean_params.clone();
    for (slot, ty) in &source_slot_types {
        if ty == "boolean" && !param_slots.contains(slot) {
            boolean_locals.insert(local_name(*slot, params));
        }
    }
    let array_casts: BTreeMap<String, String> =
        object_local_array_casts(cf, &insns, params, &object_locals);
    let allocations: DeferredAllocationPlan = deferred_allocation_plan(cf, code, &insns, has_this);
    let lifted: std::result::Result<MethodBody, &'static str> =
        with_object_locals(object_locals, boolean_locals, array_casts, || {
            with_deferred_allocations(allocations, || {
                match lift_structured(
                    cf,
                    code,
                    &insns,
                    params,
                    param_types,
                    &bootstraps,
                    has_this,
                    bool_return,
                ) {
                    StructuredLift::Body(body) => {
                        crate::debug::dbg_line(|| {
                            "method body lifted via structured (CFG) reconstruction".to_owned()
                        });
                        Ok(body)
                    }
                    StructuredLift::Unrecovered(reason) => Err(reason),
                    StructuredLift::Declined => {
                        crate::debug::dbg_line(|| {
                            "structured lift declined; falling back to flat linear lift".to_owned()
                        });
                        Ok(lift_method_body_flat(
                            cf,
                            &insns,
                            params,
                            &bootstraps,
                            has_this,
                            bool_return,
                        ))
                    }
                }
            })
        });
    lifted.map_err(|reason: &'static str| Error::UnrecoveredRegion { reason })
}

fn deferred_allocation_plan(
    cf: &ClassFile,
    code: &CodeAttribute,
    insns: &[Instruction],
    has_this: bool,
) -> DeferredAllocationPlan {
    let Ok(cfg): std::result::Result<Cfg, crate::decompile_struct::StructureError> =
        build_cfg(insns, code, |idx: u16| {
            crate::bytecode::class_internal_name_at(cf, idx)
        })
    else {
        return DeferredAllocationPlan::default();
    };
    plan_deferred_allocations(
        &cfg,
        insns,
        has_this,
        &|idx: u16| crate::bytecode::field_descriptor_at(cf, idx),
        &|idx: u16| crate::bytecode::method_name_descriptor_at(cf, idx),
        &|idx: u16| crate::bytecode::class_internal_name_at(cf, idx),
    )
}

fn lift_method_body_flat(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> MethodBody {
    let targets: BTreeSet<u32> = branch_targets(insns);
    let mut out: String = String::new();
    let mut stack: Vec<Expr> = Vec::new();
    let mut fully_lifted: bool = true;
    let indent: &str = "        ";

    let _ = writeln!(out, "{indent}/// irreducible CFG (native fallback)");
    for insn in insns {
        if targets.contains(&insn.pc) {
            stack.clear();
            let _ = writeln!(out, "{indent}// :L{}", insn.pc);
        }
        let lifted: LiftResult = lift_one(
            cf,
            insn,
            &mut stack,
            params,
            bootstraps,
            has_this,
            bool_return,
        );
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{indent}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{indent}{s}");
                fully_lifted = false;
            }
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Unhandled => {
                stack.clear();
                fully_lifted = false;
                let _ = writeln!(out, "{indent}// {} (stack reset)", insn.mnemonic);
            }
        }
    }
    MethodBody {
        text: out,
        fully_lifted,
    }
}

enum StructuredLift {
    Body(MethodBody),
    Declined,
    Unrecovered(&'static str),
}

fn lift_structured(
    cf: &ClassFile,
    code: &CodeAttribute,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> StructuredLift {
    let (folded, _): (Vec<Instruction>, crate::const_fold::ConstFoldReport) =
        crate::const_fold::fold_constants(cf, insns);
    let insns: &[Instruction] = &folded;
    let Ok(mut cfg): std::result::Result<Cfg, crate::decompile_struct::StructureError> =
        build_cfg(insns, code, |idx: u16| {
            cf.class_name(idx).ok().map(str::to_string)
        })
    else {
        return StructuredLift::Declined;
    };
    if !crate::decompile_struct::cfg_has_string_switch(cf, &cfg, insns) {
        let _: crate::sccp::SccpReport = crate::sccp::simplify_flattened_cfg(&mut cfg, insns);
    }
    if let Some(body) = try_reconstruct_pattern_method(
        cf,
        &cfg,
        insns,
        params,
        param_types,
        bootstraps,
        has_this,
        bool_return,
    ) {
        return StructuredLift::Body(body);
    }
    if let Some(body) = try_reconstruct_instanceof_deconstruction(
        cf,
        &cfg,
        insns,
        params,
        param_types,
        bootstraps,
        has_this,
        bool_return,
    ) {
        return StructuredLift::Body(body);
    }
    if bool_return
        && let Some(body) = try_reconstruct_boolean_method(
            cf,
            &cfg,
            insns,
            params,
            param_types,
            bootstraps,
            has_this,
        )
    {
        return StructuredLift::Body(body);
    }
    let dom: Dominators = compute_dominators(&cfg);
    let loops: Vec<NaturalLoop> = find_natural_loops(&cfg, &dom);
    let mut structurer: Structurer<'_> = Structurer::new(&cfg, &dom, &loops, insns).with_class(cf);
    if let Some(reason) = structurer.unmodelled_finally_reason() {
        return StructuredLift::Unrecovered(reason);
    }
    let root: Region = structurer.structure();
    if let Some(reason) = structurer.structured_finally_defect() {
        return StructuredLift::Unrecovered(reason);
    }
    let string_switch_tables: BTreeMap<BlockId, crate::decompile_struct::StringSwitchTable> =
        structurer.take_string_switch_tables();
    let finally_inline_skips: BTreeMap<BlockId, usize> = structurer.take_finally_inline_skips();
    let finally_tail_trims: BTreeMap<BlockId, usize> = structurer.take_finally_tail_trims();
    let finally_return_stores: BTreeMap<BlockId, u16> = structurer.take_finally_return_stores();
    let finally_exception_slots: BTreeSet<u16> = structurer.take_finally_exception_slots();
    let finally_catch_parameter_slots: BTreeSet<u16> =
        structurer.take_finally_catch_parameter_slots();
    let finally_scoped_local_slots: BTreeSet<u16> = structurer.take_finally_scoped_local_slots();
    let block_entry_stacks: BTreeMap<BlockId, Vec<Expr>> =
        compute_block_entry_stacks(cf, &cfg, insns, params, bootstraps, has_this, bool_return);
    let reused_exc_slots: BTreeSet<u16> = reused_exception_slots(insns, &cfg.exception_regions);
    let bool_array_names: BTreeMap<String, u8> =
        boolean_array_names(cf, insns, params, param_types);
    let slot_types: BTreeMap<u16, String> =
        compute_slot_types(cf, insns, params, param_types, &cfg.exception_regions);
    let mut ctx: RenderCtx<'_> = RenderCtx {
        cf,
        cfg: &cfg,
        insns,
        params,
        bootstraps,
        rendered_blocks: BTreeSet::new(),
        fully_lifted: !structurer.had_irreducible,
        block_entry_stacks,
        has_this,
        bool_return,
        pending_handler_seed: None,
        handler_entry_skips: BTreeSet::new(),
        finally_catch_parameter_slots,
        finally_scoped_local_slots,
        declared_finally_scoped_local_slots: BTreeSet::new(),
        pattern_binding_slots: BTreeSet::new(),
        catch_var_counter: 0,
        reused_exc_slots,
        bool_array_names,
        string_switch_tables,
        slot_types,
        param_types: param_types.clone(),
        foreach_suppress_slots: BTreeSet::new(),
        foreach_hidden_slots: BTreeSet::new(),
        finally_inline_skips,
        finally_tail_trims,
        finally_return_stores,
    };
    let mut out: String = String::new();
    render_region(&mut ctx, &root, &mut out, 2);
    append_unrendered_terminal_tail(&mut ctx, insns, &root, &mut out);
    append_shared_fallthrough_tail(&ctx, insns, &root, &mut out);
    let mut hidden_slots: BTreeSet<u16> = ctx.pattern_binding_slots.clone();
    hidden_slots.extend(ctx.foreach_hidden_slots.iter().copied());
    hidden_slots.extend(finally_exception_slots.iter().copied());
    hidden_slots.extend(ctx.finally_catch_parameter_slots.iter().copied());
    hidden_slots.extend(ctx.finally_scoped_local_slots.iter().copied());
    hidden_slots.extend(ctx.finally_return_stores.values().copied());
    let decls: String = render_slot_declarations(&ctx.slot_types, &hidden_slots);
    let body: String = hoist_loop_captured_locals(&format!("{decls}{out}"));
    StructuredLift::Body(MethodBody {
        text: body,
        fully_lifted: ctx.fully_lifted,
    })
}

fn hoist_loop_captured_locals(body: &str) -> String {
    let captured: BTreeSet<String> = lambda_captured_locals(body);
    if captured.is_empty() {
        return body.to_string();
    }
    let lines: Vec<&str> = body.lines().collect();
    let mut decl_type: BTreeMap<String, String> = BTreeMap::new();
    let mut decl_line: BTreeMap<String, usize> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some((ty, var)) = parse_bare_declaration(line)
            && captured.contains(&var)
        {
            decl_type.insert(var.clone(), ty);
            decl_line.insert(var, i);
        }
    }
    let mut hoist_assign_line: BTreeMap<String, usize> = BTreeMap::new();
    for var in decl_type.keys() {
        let assigns: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l): &(usize, &&str)| l.trim_start().starts_with(&format!("{var} = ")))
            .map(|(i, _): (usize, &&str)| i)
            .collect();
        if assigns.len() == 1 {
            let only: usize = assigns[0];
            if line_indent(lines[only]) > 8 && var_only_in_assign_and_lambda(&lines, var, only) {
                hoist_assign_line.insert(var.clone(), only);
            }
        }
    }
    hoist_assign_line.retain(|var: &String, _| decl_line.contains_key(var));
    if hoist_assign_line.is_empty() {
        return body.to_string();
    }
    let drop_decls: BTreeSet<usize> = hoist_assign_line
        .keys()
        .filter_map(|var: &String| decl_line.get(var).copied())
        .collect();
    let mut out: String = String::new();
    for (i, line) in lines.iter().enumerate() {
        if drop_decls.contains(&i) {
            continue;
        }
        if let Some(var) = hoist_assign_line
            .iter()
            .find(|(_, idx): &(&String, &usize)| **idx == i)
            .map(|(v, _): (&String, &usize)| v.clone())
            && let Some(ty) = decl_type.get(&var)
        {
            let indent: String = " ".repeat(line_indent(line));
            let rest: &str = line.trim_start();
            let _ = writeln!(out, "{indent}final {ty} {rest}");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn var_only_in_assign_and_lambda(lines: &[&str], var: &str, assign_idx: usize) -> bool {
    let pattern: String = format!("{var} = ");
    for (i, line) in lines.iter().enumerate() {
        if !line_mentions_token(line, var) {
            continue;
        }
        if i == assign_idx && line.trim_start().starts_with(&pattern) {
            continue;
        }
        let mentions_outside_lambda: bool = line
            .split(RECOMPILE_SAFE_LAMBDA_PREFIX)
            .next()
            .is_some_and(|head: &str| line_mentions_token(head, var));
        let declares: bool =
            line_indent(line) == 8 && line.trim().ends_with(';') && !line.contains('=');
        if mentions_outside_lambda && !declares {
            return false;
        }
    }
    true
}

fn line_mentions_token(text: &str, var: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let mut from: usize = 0;
    while let Some(rel) = text[from..].find(var) {
        let pos: usize = from + rel;
        let before_ok: bool = pos == 0 || !is_ident_byte(bytes[pos - 1]);
        let after: usize = pos + var.len();
        let after_ok: bool = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        from = pos + var.len();
    }
    false
}

const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn lambda_captured_locals(body: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let mut rest: &str = line;
        while let Some(pos) = rest.find(RECOMPILE_SAFE_LAMBDA_PREFIX) {
            let after: &str = &rest[pos..];
            let Some(open) = after.find('(') else {
                break;
            };
            let Some(close) = after[open..].find(')') else {
                break;
            };
            let args: &str = &after[open + 1..open + close];
            for arg in args.split(',') {
                let token: &str = arg.trim().trim_start_matches("(int) ").trim();
                if is_synthetic_local(token) {
                    out.insert(token.to_string());
                }
            }
            rest = &after[open + close..];
        }
    }
    out
}

fn is_synthetic_local(token: &str) -> bool {
    token.len() > 3
        && token.starts_with("var")
        && token[3..].bytes().all(|b: u8| b.is_ascii_digit())
}

fn parse_bare_declaration(line: &str) -> Option<(String, String)> {
    if line_indent(line) != 8 {
        return None;
    }
    let inner: &str = line.trim().strip_suffix(';')?;
    if inner.contains('=') || inner.contains('(') {
        return None;
    }
    let (ty, var): (&str, &str) = inner.rsplit_once(' ')?;
    if !is_synthetic_local(var) || ty.is_empty() {
        return None;
    }
    Some((ty.to_string(), var.to_string()))
}

fn line_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn append_shared_fallthrough_tail(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    root: &Region,
    out: &mut String,
) {
    let Some(last): Option<&Instruction> = insns.last() else {
        return;
    };
    if !matches!(last.opcode, 0xAC..=0xB0 | 0xBF) {
        return;
    }
    if !region_falls_through(root, ctx.cfg) {
        return;
    }
    let tail_bid: BlockId = match ctx.cfg.blocks.iter().rev().find(|b: &&BasicBlock| {
        let (start, end): (usize, usize) = b.insn_range;
        end > start
            && insns
                .get(end - 1)
                .is_some_and(|i: &Instruction| i.pc == last.pc)
    }) {
        Some(b) => b.id,
        None => return,
    };
    if ctx.finally_tail_trims.contains_key(&tail_bid) {
        return;
    }
    if !ctx.rendered_blocks.contains(&tail_bid) {
        return;
    }
    if let Some(stmt) = shared_terminal_tail_statement(ctx, tail_bid) {
        if stmt.contains(HOLE_RENDER) {
            return;
        }
        let already_emitted: bool = out
            .lines()
            .rev()
            .find(|l: &&str| !l.trim().is_empty())
            .is_some_and(|l: &str| l.trim() == stmt.trim());
        if already_emitted {
            return;
        }
        let _ = writeln!(out, "{}{stmt}", indent_string(2));
    }
}

fn region_falls_through(region: &Region, cfg: &Cfg) -> bool {
    match region {
        Region::Block(bid) => {
            let block: &BasicBlock = &cfg.blocks[bid.0 as usize];
            let (_start, end): (usize, usize) = block.insn_range;
            end == 0 || !block.successors.is_empty()
        }
        Region::Sequence(items) => items
            .last()
            .is_none_or(|r: &Region| region_falls_through(r, cfg)),
        Region::IfThen { .. } => true,
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => region_falls_through(then_body, cfg) || region_falls_through(else_body, cfg),
        Region::While { .. } | Region::DoWhile { .. } => true,
        Region::Switch { cases, default, .. } => {
            default
                .as_deref()
                .is_none_or(|d: &Region| region_falls_through(d, cfg))
                || cases
                    .iter()
                    .any(|(_, body): &(SwitchKey, Region)| region_falls_through(body, cfg))
        }
        Region::Try { try_body, handlers } => {
            region_falls_through(try_body, cfg)
                || handlers
                    .iter()
                    .any(|(_, body): &(Vec<String>, Region)| region_falls_through(body, cfg))
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_completes_normally,
            ..
        } => {
            *finally_completes_normally
                && (region_falls_through(try_body, cfg)
                    || handlers
                        .iter()
                        .any(|(_, body): &(Vec<String>, Region)| region_falls_through(body, cfg)))
        }
        Region::TryWithResources { try_body, .. } => region_falls_through(try_body, cfg),
        Region::Synchronized { body, .. } => region_falls_through(body, cfg),
        Region::LabeledLoop { body, .. } => region_falls_through(body, cfg),
        Region::Break { .. } | Region::Continue { .. } => false,
        Region::Irreducible { .. } => true,
    }
}

fn shared_terminal_tail_statement(ctx: &RenderCtx<'_>, bid: BlockId) -> Option<String> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    if start >= end {
        return None;
    }
    let last: &Instruction = &ctx.insns[end - 1];
    if !matches!(last.opcode, 0xAC..=0xB0 | 0xBF) {
        return None;
    }
    for ins in &ctx.insns[start..end - 1] {
        if store_target_slot(ins).is_some()
            || matches!(ins.opcode, 0xB3 | 0xB5 | 0x54..=0x56 | 0x4F..=0x53 | 0xC2 | 0xC3)
        {
            return None;
        }
    }
    let mut stack: Vec<Expr> = ctx
        .block_entry_stacks
        .get(&bid)
        .cloned()
        .unwrap_or_default();
    for ins in &ctx.insns[start..end - 1] {
        if matches!(
            ins.opcode,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            continue;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            _ => return None,
        }
    }
    match lift_one(
        ctx.cf,
        last,
        &mut stack,
        ctx.params,
        ctx.bootstraps,
        ctx.has_this,
        ctx.bool_return,
    ) {
        LiftResult::Statement(s) => Some(format!("{s};")),
        _ => None,
    }
}

fn append_unrendered_terminal_tail(
    ctx: &mut RenderCtx<'_>,
    insns: &[Instruction],
    root: &Region,
    out: &mut String,
) {
    let Some(last): Option<&Instruction> = insns.last() else {
        return;
    };
    if !matches!(last.opcode, 0xAC..=0xB0 | 0xBF) {
        return;
    }
    if !region_falls_through(root, ctx.cfg) {
        return;
    }
    let tail_bid: BlockId = match ctx.cfg.blocks.iter().rev().find(|b: &&BasicBlock| {
        let (start, end): (usize, usize) = b.insn_range;
        end > start
            && insns
                .get(end - 1)
                .is_some_and(|i: &Instruction| i.pc == last.pc)
    }) {
        Some(b) => b.id,
        None => return,
    };
    if ctx.rendered_blocks.contains(&tail_bid) {
        return;
    }
    let tail_block: &BasicBlock = &ctx.cfg.blocks[tail_bid.0 as usize];
    let preds_all_rendered: bool = tail_block
        .predecessors
        .iter()
        .all(|p: &BlockId| ctx.rendered_blocks.contains(p));
    if tail_block.predecessors.is_empty() || !preds_all_rendered {
        return;
    }
    render_block(ctx, tail_bid, out, 2);
}

enum BoolNode {
    True,

    False,

    Join,

    Cond {
        cond: String,
        taken: BlockId,
        fallthrough: BlockId,
        prelude: String,
    },
}

fn try_reconstruct_boolean_method(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
) -> Option<MethodBody> {
    let mut nodes: Vec<BoolNode> = Vec::with_capacity(cfg.blocks.len());
    let (mut trues, mut falses, mut joins): (usize, usize, usize) = (0, 0, 0);
    for block in &cfg.blocks {
        let allow_prelude: bool = block.id == cfg.entry;
        let node: BoolNode = classify_bool_block(
            cf,
            cfg,
            insns,
            params,
            bootstraps,
            has_this,
            block,
            allow_prelude,
        )?;
        match node {
            BoolNode::True => trues += 1,
            BoolNode::False => falses += 1,
            BoolNode::Join => joins += 1,
            BoolNode::Cond { .. } => {}
        }
        nodes.push(node);
    }
    if trues == 0 || falses == 0 || joins != 1 || nodes.len() < 3 {
        return None;
    }
    if !matches!(nodes.get(cfg.entry.0 as usize), Some(BoolNode::Cond { .. })) {
        return None;
    }
    let mut visiting: BTreeSet<BlockId> = BTreeSet::new();
    let expr: String = eval_bool_node(&nodes, cfg.entry, &mut visiting)?;
    let prelude: &str = match nodes.get(cfg.entry.0 as usize)? {
        BoolNode::Cond { prelude, .. } => prelude.as_str(),
        _ => "",
    };
    let decls: String = local_declarations(
        cf,
        insns,
        params,
        param_types,
        &cfg.exception_regions,
        &BTreeSet::new(),
    );
    Some(MethodBody {
        text: format!("{decls}{prelude}        return {expr};\n"),
        fully_lifted: true,
    })
}

fn classify_bool_block(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    block: &BasicBlock,
    allow_prelude: bool,
) -> Option<BoolNode> {
    let (start, end): (usize, usize) = block.insn_range;
    let body: &[Instruction] = insns.get(start..end)?;
    let last: &Instruction = body.last()?;
    if matches!(last.opcode, 0xAC) {
        if body.len() == 1 {
            return Some(BoolNode::Join);
        }
        return None;
    }
    let value_tail: &[Instruction] = match last.opcode {
        0xA7 | 0xC8 => &body[..body.len() - 1],
        _ => body,
    };
    if let Some(lit) = bool_sink_literal(value_tail) {
        return match lit {
            "true" => Some(BoolNode::True),
            _ => Some(BoolNode::False),
        };
    }
    if !matches!(last.opcode, 0x99..=0xA6 | 0xC6 | 0xC7) {
        return None;
    }
    let taken: BlockId = block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))
        .map(|e| e.target)?;
    let fallthrough: BlockId = block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondFalse | EdgeKind::Fallthrough))
        .map(|e| e.target)?;
    if taken == block.id || fallthrough == block.id {
        return None;
    }
    let _ = cfg;
    let mut stack: Vec<Expr> = Vec::new();
    let mut prelude: String = String::new();
    for ins in &body[..body.len() - 1] {
        match lift_one(cf, ins, &mut stack, params, bootstraps, has_this, true) {
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Statement(s) if allow_prelude && stack.is_empty() => {
                if s.contains(HOLE_RENDER) {
                    return None;
                }
                let _ = writeln!(prelude, "        {s};");
            }
            _ => return None,
        }
    }
    if stack.iter().any(expr_has_hole) {
        return None;
    }
    let cond: String = render_branch_condition(last, &mut stack, &BTreeMap::new());
    if cond == "true" || cond.contains(HOLE_RENDER) || !stack.is_empty() {
        return None;
    }
    Some(BoolNode::Cond {
        cond,
        taken,
        fallthrough,
        prelude,
    })
}

fn bool_sink_literal(value_tail: &[Instruction]) -> Option<&'static str> {
    match value_tail {
        [only] => match only.opcode {
            0x04 => Some("true"),
            0x03 => Some("false"),
            _ => None,
        },
        _ => None,
    }
}

fn eval_bool_node(
    nodes: &[BoolNode],
    bid: BlockId,
    visiting: &mut BTreeSet<BlockId>,
) -> Option<String> {
    match nodes.get(bid.0 as usize)? {
        BoolNode::True => Some("true".to_string()),
        BoolNode::False => Some("false".to_string()),
        BoolNode::Join => None,
        BoolNode::Cond {
            cond,
            taken,
            fallthrough,
            ..
        } => {
            if !visiting.insert(bid) {
                return None;
            }
            let taken_expr: String = eval_bool_node(nodes, *taken, visiting)?;
            let fall_expr: String = eval_bool_node(nodes, *fallthrough, visiting)?;
            visiting.remove(&bid);
            Some(combine_bool(cond, &taken_expr, &fall_expr))
        }
    }
}

fn combine_bool(cond: &str, taken: &str, fallthrough: &str) -> String {
    match (taken, fallthrough) {
        ("true", "false") => cond.to_string(),
        ("false", "true") => invert(cond),
        ("true", other) => format!("({cond}) || ({other})"),
        ("false", other) => format!("({}) && ({other})", invert(cond)),
        (other, "false") => format!("({cond}) && ({other})"),
        (other, "true") => format!("({}) || ({other})", invert(cond)),
        (t, f) => format!("({cond}) ? ({t}) : ({f})"),
    }
}

fn local_declarations(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    exception_regions: &[ExceptionRegion],
    pattern_slots: &BTreeSet<u16>,
) -> String {
    let slot_type: BTreeMap<u16, String> =
        compute_slot_types(cf, insns, params, param_types, exception_regions);
    render_slot_declarations(&slot_type, pattern_slots)
}

fn render_slot_declarations(slot_type: &BTreeMap<u16, String>, hidden: &BTreeSet<u16>) -> String {
    let mut out: String = String::new();
    for (slot, ty) in slot_type {
        if hidden.contains(slot) {
            continue;
        }
        let _ = writeln!(out, "        {ty} var{slot};");
    }
    out
}

fn compute_slot_types(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    exception_regions: &[ExceptionRegion],
) -> BTreeMap<u16, String> {
    let param_slots: BTreeSet<u16> = params.iter().map(|(i, _)| *i).collect();
    let reused_exc: BTreeSet<u16> = reused_exception_slots(insns, exception_regions);
    let exc_conflicted: BTreeSet<u16> = exception_value_conflicted_slots(insns, exception_regions);
    let handler_pcs: BTreeSet<u32> = exception_regions
        .iter()
        .map(|r: &ExceptionRegion| r.handler_pc)
        .collect();
    let seen_types: BTreeMap<u16, BTreeSet<String>> = reference_seen_types(cf, insns, &handler_pcs);
    let mut inferred: BTreeMap<u16, String> =
        infer_reference_local_types(cf, insns, param_types, &handler_pcs);
    for (slot, ty) in constructed_local_types(cf, insns) {
        let conflicts_with_seen: bool = seen_types
            .get(&slot)
            .is_some_and(|tys: &BTreeSet<String>| tys.iter().any(|t: &String| *t != ty));
        if exc_conflicted.contains(&slot) || conflicts_with_seen {
            inferred.insert(slot, "Object".to_string());
        } else {
            inferred.insert(slot, ty);
        }
    }
    for (slot, ty) in constructed_array_local_types(cf, insns) {
        let conflicts_with_seen: bool = seen_types
            .get(&slot)
            .is_some_and(|tys: &BTreeSet<String>| tys.iter().any(|t: &String| *t != ty));
        if exc_conflicted.contains(&slot) || conflicts_with_seen {
            inferred.insert(slot, "Object".to_string());
        } else {
            inferred.insert(slot, ty);
        }
    }
    for (slot, ty) in exception_local_types(insns, exception_regions) {
        if reused_exc.contains(&slot) {
            continue;
        }
        inferred.entry(slot).or_insert(ty);
    }
    let bool_scalar: BTreeSet<u16> = boolean_scalar_local_slots(cf, insns, params, param_types);
    let mut slot_type: BTreeMap<u16, String> = BTreeMap::new();
    for insn in insns {
        let ty: &'static str = match insn.opcode {
            0x36 | 0x3B..=0x3E => "int",
            0x37 | 0x3F..=0x42 => "long",
            0x38 | 0x43..=0x46 => "float",
            0x39 | 0x47..=0x4A => "double",
            0x3A | 0x4B..=0x4E => "Object",
            _ => continue,
        };
        let slot: u16 = match (insn.opcode, &insn.operands) {
            (0x36..=0x3A, Operands::Local(idx)) => *idx,
            (0x3B..=0x3E, _) => u16::from(insn.opcode - 0x3B),
            (0x3F..=0x42, _) => u16::from(insn.opcode - 0x3F),
            (0x43..=0x46, _) => u16::from(insn.opcode - 0x43),
            (0x47..=0x4A, _) => u16::from(insn.opcode - 0x47),
            (0x4B..=0x4E, _) => u16::from(insn.opcode - 0x4B),
            _ => continue,
        };
        if param_slots.contains(&slot) {
            continue;
        }
        if reused_exc.contains(&slot) && matches!(insn.opcode, 0x3A | 0x4B..=0x4E) {
            continue;
        }
        let resolved: String = if ty == "Object" {
            inferred
                .get(&slot)
                .cloned()
                .unwrap_or_else(|| "Object".to_string())
        } else if matches!(insn.opcode, 0x36 | 0x3B..=0x3E) && bool_scalar.contains(&slot) {
            "boolean".to_string()
        } else {
            ty.to_string()
        };
        slot_type
            .entry(slot)
            .and_modify(|cur: &mut String| {
                if *cur != resolved {
                    *cur = "Object".to_string();
                }
            })
            .or_insert(resolved);
    }
    for &slot in &reused_exc {
        if param_slots.contains(&slot) || slot_type.contains_key(&slot) {
            continue;
        }
        let resolved: String = inferred
            .get(&slot)
            .cloned()
            .unwrap_or_else(|| "Object".to_string());
        slot_type.insert(slot, resolved);
    }
    slot_type
}

fn boolean_array_names(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
) -> BTreeMap<String, u8> {
    let mut ranks: BTreeMap<String, u8> =
        infer_reference_local_types(cf, insns, param_types, &BTreeSet::new())
            .into_iter()
            .filter_map(|(slot, ty): (u16, String)| {
                boolean_array_rank(Some(ty.as_str()))
                    .map(|rank: u8| (local_name(slot, params), rank))
            })
            .collect();
    for (slot, ty) in param_types {
        let rank: Option<u8> = boolean_array_rank(Some(ty.as_str()));
        if let Some(rank) = rank {
            ranks.insert(local_name(*slot, params), rank);
        }
    }
    ranks
}

fn boolean_array_expr_rank(expr: &Expr, ranks: &BTreeMap<String, u8>) -> Option<u8> {
    match expr {
        Expr::Local(name) => ranks.get(name).copied(),
        Expr::ArrayLoad { array, .. } => {
            boolean_array_expr_rank(array, ranks).and_then(|rank: u8| rank.checked_sub(1))
        }
        _ => None,
    }
}

fn is_boolean_element_array(expr: &Expr, ranks: &BTreeMap<String, u8>) -> bool {
    boolean_array_expr_rank(expr, ranks) == Some(1)
}

#[derive(Clone, Copy)]
enum BoolScalarVal {
    BoolArray(u8),
    BoolScalar,
    ZeroOrOne,
    Other,
}

fn field_descriptor_is_boolean(cf: &ClassFile, insn: &Instruction) -> bool {
    let Operands::ConstPool(idx) = &insn.operands else {
        return false;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return false;
    };
    let Some((_owner, desc)): Option<(&str, &str)> = reference.rsplit_once(':') else {
        return false;
    };
    matches!(descriptor::parse_field(desc), Some(JavaType::Boolean))
}

fn invoke_returns_boolean(cf: &ClassFile, insn: &Instruction) -> bool {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return false,
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, idx) else {
        return false;
    };
    let Some((_member, desc)): Option<(&str, &str)> = reference.rsplit_once(':') else {
        return false;
    };
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(desc) else {
        return false;
    };
    matches!(parsed.returns, JavaType::Boolean)
}

fn conditional_boolean_store_slots(insns: &[Instruction]) -> BTreeSet<u16> {
    let mut out: BTreeSet<u16> = BTreeSet::new();
    for (i, window) in insns.windows(5).enumerate() {
        let [head, second, jump, fourth, fifth]: &[Instruction] = window else {
            continue;
        };
        if matches!(head.opcode, 0x99..=0xA6 | 0xC6 | 0xC7)
            && matches!((second.opcode, fourth.opcode), (0x04, 0x03) | (0x03, 0x04))
            && jump.opcode == 0xA7
            && branch_target(head) == Some(fourth.pc)
            && branch_target(jump) == Some(fifth.pc)
            && let Some(slot) = int_store_slot(fifth)
        {
            out.insert(slot);
            continue;
        }
        if matches!((head.opcode, fourth.opcode), (0x04, 0x03) | (0x03, 0x04))
            && jump.opcode == 0xA7
            && let Some(slot) = int_store_slot(second)
            && int_store_slot(fifth) == Some(slot)
            && let Some(next) = insns.get(i + 5)
            && branch_target(jump) == Some(next.pc)
        {
            out.insert(slot);
        }
    }
    out
}

fn int_store_slot(insn: &Instruction) -> Option<u16> {
    matches!(insn.opcode, 0x36 | 0x3B..=0x3E)
        .then(|| store_target_slot(insn))
        .flatten()
}

fn boolean_array_rank(ty: Option<&str>) -> Option<u8> {
    let ty: &str = ty?;
    let base: &str = ty.trim_end_matches("[]");
    if base != "boolean" {
        return None;
    }
    let brackets: usize = ty.len() - base.len();
    if brackets == 0 || !brackets.is_multiple_of(2) {
        return None;
    }
    u8::try_from(brackets / 2).ok()
}

fn boolean_scalar_local_slots(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
) -> BTreeSet<u16> {
    let mut bool_array_slots: BTreeMap<u16, u8> =
        infer_reference_local_types(cf, insns, param_types, &BTreeSet::new())
            .into_iter()
            .filter_map(|(slot, ty): (u16, String)| {
                boolean_array_rank(Some(ty.as_str())).map(|rank: u8| (slot, rank))
            })
            .collect();
    for (slot, ty) in param_types {
        let rank: Option<u8> = boolean_array_rank(Some(ty.as_str()));
        if let Some(rank) = rank {
            bool_array_slots.insert(*slot, rank);
        }
    }
    let param_slots: BTreeSet<u16> = params.iter().map(|(i, _): &(u16, String)| *i).collect();
    let array_of = |val: Option<&str>| -> BoolScalarVal {
        boolean_array_rank(val).map_or(BoolScalarVal::Other, BoolScalarVal::BoolArray)
    };
    let slot_val = |slot: Option<u16>| -> BoolScalarVal {
        slot.and_then(|s: u16| bool_array_slots.get(&s).copied())
            .map_or(BoolScalarVal::Other, BoolScalarVal::BoolArray)
    };
    let mut stack: Vec<BoolScalarVal> = Vec::new();
    let mut bool_stores: BTreeSet<u16> = BTreeSet::new();
    let mut other_stores: BTreeSet<u16> = BTreeSet::new();
    for insn in insns {
        let op: u8 = insn.opcode;
        match op {
            0x03 | 0x04 => stack.push(BoolScalarVal::ZeroOrOne),
            0x02 | 0x05..=0x18 | 0x1A..=0x29 => stack.push(BoolScalarVal::Other),
            0x19 => {
                let slot: Option<u16> = match &insn.operands {
                    Operands::Local(idx) => Some(*idx),
                    _ => None,
                };
                stack.push(slot_val(slot));
            }
            0x2A..=0x2D => stack.push(slot_val(Some(u16::from(op - 0x2A)))),
            0xB2 | 0xB4 => {
                if op == 0xB4 {
                    stack.pop();
                }
                stack.push(if field_descriptor_is_boolean(cf, insn) {
                    BoolScalarVal::BoolScalar
                } else {
                    array_of(field_static_type(cf, insn).as_deref())
                });
            }
            0xBC | 0xBD => {
                stack.pop();
                stack.push(array_of(new_array_static_type(cf, insn).as_deref()));
            }
            0xB6..=0xB9 => {
                let argc: usize = invoke_pop_count(cf, insn, op);
                for _ in 0..argc {
                    stack.pop();
                }
                let ret: Option<String> = invoke_return_type(cf, insn);
                if invoke_returns_boolean(cf, insn) {
                    stack.push(BoolScalarVal::BoolScalar);
                } else if !matches!(ret.as_deref(), Some("void")) {
                    stack.push(array_of(ret.as_deref()));
                }
            }
            0xC0 => {
                stack.pop();
                stack.push(array_of(checkcast_static_type(cf, insn).as_deref()));
            }
            0x59 => stack.push(stack.last().copied().unwrap_or(BoolScalarVal::Other)),
            0x32 => {
                stack.pop();
                let array: BoolScalarVal = stack.pop().unwrap_or(BoolScalarVal::Other);
                stack.push(match array {
                    BoolScalarVal::BoolArray(rank) if rank >= 2 => {
                        BoolScalarVal::BoolArray(rank - 1)
                    }
                    _ => BoolScalarVal::Other,
                });
            }
            0x33 => {
                stack.pop();
                let array: BoolScalarVal = stack.pop().unwrap_or(BoolScalarVal::Other);
                stack.push(match array {
                    BoolScalarVal::BoolArray(1) => BoolScalarVal::BoolScalar,
                    _ => BoolScalarVal::Other,
                });
            }
            0x2E..=0x31 | 0x34 | 0x35 => {
                stack.pop();
                stack.pop();
                stack.push(BoolScalarVal::Other);
            }
            0xC5 => {
                let dims: usize = match &insn.operands {
                    Operands::MultiANewArray { dimensions, .. } => usize::from(*dimensions),
                    _ => 0,
                };
                for _ in 0..dims {
                    stack.pop();
                }
                stack.push(array_of(multi_new_array_static_type(cf, insn).as_deref()));
            }
            0x36 | 0x3B..=0x3E => {
                let value: BoolScalarVal = stack.pop().unwrap_or(BoolScalarVal::Other);
                let slot: u16 = match (op, &insn.operands) {
                    (0x36, Operands::Local(idx)) => *idx,
                    (0x3B..=0x3E, _) => u16::from(op - 0x3B),
                    _ => continue,
                };
                match value {
                    BoolScalarVal::BoolScalar => {
                        bool_stores.insert(slot);
                    }
                    BoolScalarVal::ZeroOrOne => {}
                    BoolScalarVal::BoolArray(_) | BoolScalarVal::Other => {
                        other_stores.insert(slot);
                    }
                }
            }
            _ => stack.clear(),
        }
    }
    bool_stores.extend(conditional_boolean_store_slots(insns));
    bool_stores
        .into_iter()
        .filter(|slot: &u16| !other_stores.contains(slot) && !param_slots.contains(slot))
        .collect()
}

fn update_live(live: &mut BTreeMap<u16, String>, slot: u16, ty: Option<String>) {
    match ty {
        Some(t) => {
            live.insert(slot, t);
        }
        None => {
            live.remove(&slot);
        }
    }
}

fn infer_reference_local_types(
    cf: &ClassFile,
    insns: &[Instruction],
    param_types: &BTreeMap<u16, String>,
    handler_pcs: &BTreeSet<u32>,
) -> BTreeMap<u16, String> {
    infer_reference_local_slots(cf, insns, param_types, handler_pcs)
        .0
        .into_iter()
        .filter_map(|(slot, ty): (u16, Option<String>)| ty.map(|t: String| (slot, t)))
        .filter(|(_, t): &(u16, String)| t != "Object" && t != "void")
        .collect()
}

fn reference_seen_types(
    cf: &ClassFile,
    insns: &[Instruction],
    handler_pcs: &BTreeSet<u32>,
) -> BTreeMap<u16, BTreeSet<String>> {
    infer_reference_local_slots(cf, insns, &BTreeMap::new(), handler_pcs).1
}

fn infer_reference_local_slots(
    cf: &ClassFile,
    insns: &[Instruction],
    param_types: &BTreeMap<u16, String>,
    handler_pcs: &BTreeSet<u32>,
) -> (
    BTreeMap<u16, Option<String>>,
    BTreeMap<u16, BTreeSet<String>>,
) {
    let mut type_stack: Vec<Option<String>> = Vec::new();
    let mut slots: BTreeMap<u16, Option<String>> = BTreeMap::new();
    let mut distinct: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    let mut live_types: BTreeMap<u16, String> = param_types.clone();
    let record = |slots: &mut BTreeMap<u16, Option<String>>,
                  distinct: &mut BTreeMap<u16, BTreeSet<String>>,
                  slot: u16,
                  ty: Option<String>| {
        if let Some(t) = &ty
            && t != "Object"
            && t != "void"
        {
            distinct.entry(slot).or_default().insert(t.clone());
        }
        match slots.get(&slot) {
            Some(Some(existing)) if Some(existing) != ty.as_ref() => {
                slots.insert(slot, None);
            }
            Some(None) => {}
            _ => {
                slots.insert(slot, ty);
            }
        }
    };
    for insn in insns {
        let op: u8 = insn.opcode;
        match op {
            0x01 => type_stack.push(None),
            0x12..=0x14 => type_stack.push(ldc_static_type(cf, insn)),
            0xBB => type_stack.push(new_static_type(cf, insn)),
            0xBC | 0xBD => {
                type_stack.pop();
                type_stack.push(new_array_static_type(cf, insn));
            }
            0xC5 => {
                let ty: Option<String> = multi_new_array_static_type(cf, insn);
                let dims: usize = match &insn.operands {
                    Operands::MultiANewArray { dimensions, .. } => usize::from(*dimensions),
                    _ => 0,
                };
                for _ in 0..dims {
                    type_stack.pop();
                }
                type_stack.push(ty);
            }
            0x15..=0x18 | 0x1A..=0x29 => type_stack.push(None),
            0x32 => {
                type_stack.pop();
                let array_ty: Option<String> = type_stack.pop().flatten();
                type_stack
                    .push(array_ty.and_then(|t: String| t.strip_suffix("[]").map(str::to_owned)));
            }
            0xC0 => {
                type_stack.pop();
                type_stack.push(checkcast_static_type(cf, insn));
            }
            0xB2 | 0xB4 => {
                if op == 0xB4 {
                    type_stack.pop();
                }
                type_stack.push(field_static_type(cf, insn));
            }
            0xB6..=0xB9 => {
                let ret: Option<String> = invoke_return_type(cf, insn);
                let argc: usize = invoke_pop_count(cf, insn, op);
                for _ in 0..argc {
                    type_stack.pop();
                }
                if !matches!(ret.as_deref(), Some("void")) {
                    type_stack.push(ret);
                }
            }
            0xBA => {
                let ret: Option<String> = invoke_dynamic_return_type(cf, insn);
                let argc: usize = invoke_dynamic_pop_count(cf, insn);
                for _ in 0..argc {
                    type_stack.pop();
                }
                if !matches!(ret.as_deref(), Some("void")) {
                    type_stack.push(ret);
                }
            }
            0x19 => {
                let slot: Option<u16> = match &insn.operands {
                    Operands::Local(idx) => Some(*idx),
                    _ => None,
                };
                type_stack.push(slot.and_then(|s: u16| live_types.get(&s).cloned()));
            }
            0x2A..=0x2D => {
                let slot: u16 = u16::from(op - 0x2A);
                type_stack.push(live_types.get(&slot).cloned());
            }
            0x3A => {
                let catch_bind: bool = handler_pcs.contains(&insn.pc) && type_stack.is_empty();
                let top: Option<String> = type_stack.pop().flatten();
                if let Operands::Local(idx) = &insn.operands
                    && !catch_bind
                {
                    record(&mut slots, &mut distinct, *idx, top.clone());
                    update_live(&mut live_types, *idx, top);
                }
            }
            0x4B..=0x4E => {
                let catch_bind: bool = handler_pcs.contains(&insn.pc) && type_stack.is_empty();
                let top: Option<String> = type_stack.pop().flatten();
                let slot: u16 = u16::from(op - 0x4B);
                if !catch_bind {
                    record(&mut slots, &mut distinct, slot, top.clone());
                    update_live(&mut live_types, slot, top);
                }
            }
            _ => {
                type_stack.clear();
            }
        }
    }
    (slots, distinct)
}

fn constructed_local_types(cf: &ClassFile, insns: &[Instruction]) -> BTreeMap<u16, String> {
    let mut out: BTreeMap<u16, String> = BTreeMap::new();
    let mut pending: Vec<String> = Vec::new();
    let mut last_constructed: Option<String> = None;
    for insn in insns {
        match insn.opcode {
            0xBB => {
                if let Some(ty) = new_static_type(cf, insn) {
                    pending.push(ty);
                }
                last_constructed = None;
            }
            0xB7 => {
                if invoke_is_init(cf, insn) {
                    last_constructed = pending.pop();
                } else {
                    last_constructed = None;
                }
            }
            0x3A | 0x4B..=0x4E => {
                if let Some(ty) = last_constructed.take() {
                    let slot: u16 = match (insn.opcode, &insn.operands) {
                        (0x3A, Operands::Local(idx)) => *idx,
                        (0x4B..=0x4E, _) => u16::from(insn.opcode - 0x4B),
                        _ => continue,
                    };
                    match out.get(&slot) {
                        Some(existing) if *existing != ty => {
                            out.insert(slot, "Object".to_string());
                        }
                        _ => {
                            out.insert(slot, ty);
                        }
                    }
                }
            }
            _ => last_constructed = None,
        }
    }
    out
}

#[derive(Clone)]
enum ArrayStackVal {
    Array(String),
    Scalar,
}

fn constructed_array_local_types(cf: &ClassFile, insns: &[Instruction]) -> BTreeMap<u16, String> {
    let mut out: BTreeMap<u16, String> = BTreeMap::new();
    let mut stack: Vec<ArrayStackVal> = Vec::new();
    for insn in insns {
        let op: u8 = insn.opcode;
        match op {
            0x01..=0x2D => stack.push(ArrayStackVal::Scalar),
            0xBC | 0xBD => {
                stack.pop();
                stack.push(
                    new_array_static_type(cf, insn)
                        .map_or(ArrayStackVal::Scalar, ArrayStackVal::Array),
                );
            }
            0xC5 => {
                let dims: usize = match &insn.operands {
                    Operands::MultiANewArray { dimensions, .. } => usize::from(*dimensions),
                    _ => 0,
                };
                for _ in 0..dims {
                    stack.pop();
                }
                stack.push(
                    multi_new_array_static_type(cf, insn)
                        .map_or(ArrayStackVal::Scalar, ArrayStackVal::Array),
                );
            }
            0x59 => {
                let top: ArrayStackVal = stack.last().cloned().unwrap_or(ArrayStackVal::Scalar);
                stack.push(top);
            }
            0x4F..=0x56 => {
                stack.pop();
                stack.pop();
                stack.pop();
            }
            0x3A | 0x4B..=0x4E => {
                let top: Option<ArrayStackVal> = stack.pop();
                let slot: u16 = match (op, &insn.operands) {
                    (0x3A, Operands::Local(idx)) => *idx,
                    (0x4B..=0x4E, _) => u16::from(op - 0x4B),
                    _ => continue,
                };
                if let Some(ArrayStackVal::Array(ty)) = top {
                    match out.get(&slot) {
                        Some(existing) if *existing != ty => {
                            out.insert(slot, "Object".to_string());
                        }
                        _ => {
                            out.insert(slot, ty);
                        }
                    }
                }
            }
            _ => stack.clear(),
        }
    }
    out
}

fn invoke_is_init(cf: &ClassFile, insn: &Instruction) -> bool {
    let Operands::ConstPool(idx) = &insn.operands else {
        return false;
    };
    bytecode::resolve_ref(cf, *idx).is_some_and(|r: String| {
        r.rsplit_once(':')
            .map(|(member, _): (&str, &str)| {
                member.ends_with(".<init>") || member.ends_with("<init>")
            })
            .unwrap_or(false)
    })
}

fn exception_local_types(
    insns: &[Instruction],
    exception_regions: &[ExceptionRegion],
) -> BTreeMap<u16, String> {
    let handler_pcs: BTreeSet<u32> = exception_regions.iter().map(|r| r.handler_pc).collect();
    let mut value_store_slots: BTreeSet<u16> = BTreeSet::new();
    for insn in insns {
        if handler_pcs.contains(&insn.pc) {
            continue;
        }
        if let Some(slot) = store_target_slot(insn) {
            value_store_slots.insert(slot);
        }
    }
    let mut out: BTreeMap<u16, String> = BTreeMap::new();
    for region in exception_regions {
        let Some(ty): Option<&String> = region.catch_type.as_ref() else {
            continue;
        };
        let Some(handler): Option<&Instruction> = insns
            .iter()
            .find(|i: &&Instruction| i.pc == region.handler_pc)
        else {
            continue;
        };
        let slot: Option<u16> = match (handler.opcode, &handler.operands) {
            (0x3A, Operands::Local(idx)) => Some(*idx),
            (0x4B..=0x4E, _) => Some(u16::from(handler.opcode - 0x4B)),
            _ => None,
        };
        if let Some(slot) = slot {
            let src_ty: String = if value_store_slots.contains(&slot) {
                "Object".to_string()
            } else {
                descriptor::binary_to_source(ty)
            };
            match out.get(&slot) {
                Some(existing) if *existing != src_ty => {
                    out.insert(slot, "Object".to_string());
                }
                _ => {
                    out.insert(slot, src_ty);
                }
            }
        }
    }
    out
}

const fn slot_op_category(opcode: u8) -> Option<bool> {
    match opcode {
        0x19 | 0x3A | 0x2A..=0x2D | 0x4B..=0x4E => Some(true),
        0x15..=0x18 | 0x36..=0x39 | 0x1A..=0x29 | 0x3B..=0x4A => Some(false),
        _ => None,
    }
}

const fn slot_op_is_store(opcode: u8) -> bool {
    matches!(opcode, 0x36..=0x4E)
}

const fn slot_load_type_index(opcode: u8) -> Option<u8> {
    match opcode {
        0x15 => Some(0),
        0x16 => Some(1),
        0x17 => Some(2),
        0x18 => Some(3),
        0x19 => Some(4),
        0x1A..=0x1D => Some(0),
        0x1E..=0x21 => Some(1),
        0x22..=0x25 => Some(2),
        0x26..=0x29 => Some(3),
        0x2A..=0x2D => Some(4),
        _ => None,
    }
}

const fn slot_store_type_index(opcode: u8) -> Option<u8> {
    match opcode {
        0x36 => Some(0),
        0x37 => Some(1),
        0x38 => Some(2),
        0x39 => Some(3),
        0x3A => Some(4),
        0x3B..=0x3E => Some(0),
        0x3F..=0x42 => Some(1),
        0x43..=0x46 => Some(2),
        0x47..=0x4A => Some(3),
        0x4B..=0x4E => Some(4),
        _ => None,
    }
}

const fn explicit_load_opcode(type_index: u8) -> u8 {
    0x15 + type_index
}

const fn explicit_store_opcode(type_index: u8) -> u8 {
    0x36 + type_index
}

fn local_slot_operand(insn: &Instruction) -> Option<u16> {
    match insn.opcode {
        0x15..=0x19 | 0x36..=0x3A => match &insn.operands {
            Operands::Local(idx) => Some(*idx),
            _ => None,
        },
        0x1A..=0x2D => Some(u16::from((insn.opcode - 0x1A) % 4)),
        0x3B..=0x4E => Some(u16::from((insn.opcode - 0x3B) % 4)),
        _ => None,
    }
}

fn rebind_slot_to_explicit(insn: &mut Instruction, fresh: u16) {
    if let Some(ti) = slot_store_type_index(insn.opcode) {
        insn.opcode = explicit_store_opcode(ti);
    } else if let Some(ti) = slot_load_type_index(insn.opcode) {
        insn.opcode = explicit_load_opcode(ti);
    } else {
        return;
    }
    insn.operands = Operands::Local(fresh);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReusedIntValue {
    Boolean,
    Integer,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReusedLocalLifetime {
    Parameter,
    Fresh,
    Mixed,
}

fn merge_reused_local_lifetime(
    current: Option<ReusedLocalLifetime>,
    incoming: ReusedLocalLifetime,
) -> ReusedLocalLifetime {
    match current {
        None => incoming,
        Some(existing) if existing == incoming => existing,
        Some(_) => ReusedLocalLifetime::Mixed,
    }
}

fn int_value_store_indices(
    cf: &ClassFile,
    insns: &[Instruction],
    slot: u16,
    boolean_param_slots: &BTreeSet<u16>,
) -> Option<BTreeSet<usize>> {
    let mut stack: Vec<ReusedIntValue> = Vec::new();
    let mut stores: BTreeSet<usize> = BTreeSet::new();
    for (index, insn) in insns.iter().enumerate() {
        let push_int_local = |stack: &mut Vec<ReusedIntValue>, local: Option<u16>| {
            stack.push(
                if local.is_some_and(|local| boolean_param_slots.contains(&local)) {
                    ReusedIntValue::Boolean
                } else {
                    ReusedIntValue::Integer
                },
            );
        };
        match insn.opcode {
            0x03 | 0x04 => stack.push(ReusedIntValue::Boolean),
            0x02 | 0x05..=0x08 | 0x10 | 0x11 => stack.push(ReusedIntValue::Integer),
            0x15 => push_int_local(
                &mut stack,
                match &insn.operands {
                    Operands::Local(local) => Some(*local),
                    _ => None,
                },
            ),
            0x1A..=0x1D => {
                push_int_local(&mut stack, Some(u16::from(insn.opcode - 0x1A)));
            }
            0x60 | 0x64 | 0x68 | 0x6C | 0x70 | 0x78 | 0x7A | 0x7C | 0x7E | 0x80 | 0x82 => {
                let right: ReusedIntValue = stack.pop().unwrap_or(ReusedIntValue::Unknown);
                let left: ReusedIntValue = stack.pop().unwrap_or(ReusedIntValue::Unknown);
                stack.push(
                    if matches!(left, ReusedIntValue::Unknown)
                        || matches!(right, ReusedIntValue::Unknown)
                    {
                        ReusedIntValue::Unknown
                    } else {
                        ReusedIntValue::Integer
                    },
                );
            }
            0x74 | 0x91..=0x93 => {
                let value: ReusedIntValue = stack.pop().unwrap_or(ReusedIntValue::Unknown);
                stack.push(if matches!(value, ReusedIntValue::Unknown) {
                    ReusedIntValue::Unknown
                } else {
                    ReusedIntValue::Integer
                });
            }
            0xB2 | 0xB4 => {
                if insn.opcode == 0xB4 {
                    stack.pop();
                }
                stack.push(if field_descriptor_is_boolean(cf, insn) {
                    ReusedIntValue::Boolean
                } else {
                    ReusedIntValue::Unknown
                });
            }
            0xB6..=0xB9 => {
                let argc: usize = invoke_pop_count(cf, insn, insn.opcode);
                for _ in 0..argc {
                    stack.pop();
                }
                let ret: Option<String> = invoke_return_type(cf, insn);
                if invoke_returns_boolean(cf, insn) {
                    stack.push(ReusedIntValue::Boolean);
                } else if !matches!(ret.as_deref(), Some("void")) {
                    stack.push(ReusedIntValue::Unknown);
                }
            }
            0x36 | 0x3B..=0x3E => {
                let value: ReusedIntValue = stack.pop().unwrap_or(ReusedIntValue::Unknown);
                if int_store_slot(insn) == Some(slot) {
                    if value != ReusedIntValue::Integer {
                        return None;
                    }
                    stores.insert(index);
                }
            }
            _ => stack.clear(),
        }
    }
    (!stores.is_empty()).then_some(stores)
}

fn instruction_successor_indices(insns: &[Instruction]) -> Option<Vec<Vec<usize>>> {
    let pc_to_index: BTreeMap<u32, usize> = insns
        .iter()
        .enumerate()
        .map(|(index, insn): (usize, &Instruction)| (insn.pc, index))
        .collect();
    if pc_to_index.len() != insns.len() {
        return None;
    }
    let mut successors: Vec<Vec<usize>> = Vec::with_capacity(insns.len());
    for (index, insn) in insns.iter().enumerate() {
        if matches!(insn.opcode, 0xA8 | 0xA9 | 0xC9) {
            return None;
        }
        let offsets: Vec<i32> = match &insn.operands {
            Operands::Branch(offset) => vec![*offset],
            Operands::TableSwitch {
                default,
                low,
                high,
                offsets,
            } => {
                if high < low {
                    return None;
                }
                let expected: usize =
                    usize::try_from(i64::from(*high) - i64::from(*low) + 1).ok()?;
                if offsets.len() != expected {
                    return None;
                }
                let mut all: Vec<i32> = Vec::with_capacity(offsets.len().saturating_add(1));
                all.push(*default);
                all.extend(offsets.iter().copied());
                all
            }
            Operands::LookupSwitch { default, pairs } => {
                if pairs
                    .windows(2)
                    .any(|pair: &[(i32, i32)]| pair[0].0 >= pair[1].0)
                {
                    return None;
                }
                let mut all: Vec<i32> = Vec::with_capacity(pairs.len().saturating_add(1));
                all.push(*default);
                all.extend(pairs.iter().map(|(_, offset): &(i32, i32)| *offset));
                all
            }
            _ => Vec::new(),
        };
        let mut current: Vec<usize> = offsets
            .into_iter()
            .map(|offset: i32| {
                let pc: u32 =
                    u32::try_from(i64::from(insn.pc).checked_add(i64::from(offset))?).ok()?;
                pc_to_index.get(&pc).copied()
            })
            .collect::<Option<Vec<usize>>>()?;
        let has_fallthrough: bool = !matches!(
            insn.opcode,
            0xA7..=0xA9 | 0xAA | 0xAB | 0xAC..=0xB1 | 0xBF | 0xC8 | 0xC9
        );
        if has_fallthrough
            && let Some(next) = index.checked_add(1).filter(|next| *next < insns.len())
        {
            current.push(next);
        }
        current.sort_unstable();
        current.dedup();
        successors.push(current);
    }
    Some(successors)
}

fn reused_boolean_parameter_plan(
    cf: &ClassFile,
    insns: &[Instruction],
    slot: u16,
    boolean_param_slots: &BTreeSet<u16>,
    successors: &[Vec<usize>],
) -> Option<BTreeSet<usize>> {
    if insns.iter().any(
        |insn: &Instruction| matches!(&insn.operands, Operands::Iinc { index, .. } if *index == slot),
    ) {
        return None;
    }
    let stores: BTreeSet<usize> = int_value_store_indices(cf, insns, slot, boolean_param_slots)?;
    let mut incoming: Vec<Option<ReusedLocalLifetime>> = vec![None; insns.len()];
    incoming[0] = Some(ReusedLocalLifetime::Parameter);
    let mut pending: Vec<usize> = vec![0];
    let mut queued: BTreeSet<usize> = BTreeSet::from([0]);
    while let Some(index) = pending.pop() {
        queued.remove(&index);
        let state: ReusedLocalLifetime = incoming[index]?;
        let outgoing: ReusedLocalLifetime = if stores.contains(&index) {
            ReusedLocalLifetime::Fresh
        } else {
            state
        };
        for &successor in &successors[index] {
            let merged: ReusedLocalLifetime =
                merge_reused_local_lifetime(incoming[successor], outgoing);
            if incoming[successor] != Some(merged) {
                incoming[successor] = Some(merged);
                if queued.insert(successor) {
                    pending.push(successor);
                }
            }
        }
    }
    let mut rewrite: BTreeSet<usize> = stores;
    for (index, insn) in insns.iter().enumerate() {
        if local_slot_operand(insn) != Some(slot) || slot_load_type_index(insn.opcode) != Some(0) {
            continue;
        }
        match incoming[index] {
            Some(ReusedLocalLifetime::Parameter) => {}
            Some(ReusedLocalLifetime::Fresh) => {
                rewrite.insert(index);
            }
            Some(ReusedLocalLifetime::Mixed) | None => return None,
        }
    }
    Some(rewrite)
}

fn split_reused_boolean_parameter_ranges(
    cf: &ClassFile,
    insns: &mut [Instruction],
    max_locals: u16,
    exception_table: &[bytecode::ExceptionEntry],
    boolean_param_slots: &BTreeSet<u16>,
) -> u16 {
    if insns.is_empty() || boolean_param_slots.is_empty() || !exception_table.is_empty() {
        return max_locals;
    }
    let Some(successors) = instruction_successor_indices(insns) else {
        return max_locals;
    };
    let plans: BTreeMap<u16, BTreeSet<usize>> = boolean_param_slots
        .iter()
        .filter_map(|slot: &u16| {
            reused_boolean_parameter_plan(cf, insns, *slot, boolean_param_slots, &successors)
                .map(|plan: BTreeSet<usize>| (*slot, plan))
        })
        .collect();
    let Ok(required): core::result::Result<u16, _> = u16::try_from(plans.len()) else {
        return max_locals;
    };
    if max_locals.checked_add(required).is_none() {
        return max_locals;
    }
    let mut next_fresh: u16 = max_locals;
    for (_, rewrite) in plans {
        let fresh: u16 = next_fresh;
        next_fresh += 1;
        for index in rewrite {
            rebind_slot_to_explicit(&mut insns[index], fresh);
        }
    }
    next_fresh
}

fn split_reused_primitive_ranges(insns: &mut [Instruction], max_locals: u16) {
    let mut category_seen: BTreeMap<u16, BTreeSet<bool>> = BTreeMap::new();
    for insn in insns.iter() {
        if let (Some(cat), Some(slot)) = (slot_op_category(insn.opcode), local_slot_operand(insn)) {
            category_seen.entry(slot).or_default().insert(cat);
        }
    }
    let split_slots: BTreeSet<u16> = category_seen
        .into_iter()
        .filter(|(slot, cats): &(u16, BTreeSet<bool>)| {
            cats.len() == 2 && slot_categories_cleanly_partitioned(insns, *slot)
        })
        .map(|(slot, _): (u16, BTreeSet<bool>)| slot)
        .collect();
    if split_slots.is_empty() {
        return;
    }
    let mut next_fresh: u16 = max_locals;
    for &slot in &split_slots {
        let fresh: u16 = next_fresh;
        next_fresh = next_fresh.saturating_add(1);
        let first_category: bool = insns
            .iter()
            .filter(|insn: &&Instruction| local_slot_operand(insn) == Some(slot))
            .find_map(|insn: &Instruction| slot_op_category(insn.opcode))
            .unwrap_or(true);
        for insn in insns.iter_mut() {
            if let Operands::Iinc { index, .. } = &mut insn.operands {
                if *index == slot && first_category {
                    *index = fresh;
                }
                continue;
            }
            if local_slot_operand(insn) != Some(slot) {
                continue;
            }
            if slot_op_category(insn.opcode) != Some(first_category) {
                rebind_slot_to_explicit(insn, fresh);
            }
        }
    }
}

fn slot_categories_cleanly_partitioned(insns: &[Instruction], slot: u16) -> bool {
    let mut first_category: Option<bool> = None;
    let mut crossed: bool = false;
    for insn in insns {
        if local_slot_operand(insn) != Some(slot) {
            continue;
        }
        let Some(cat): Option<bool> = slot_op_category(insn.opcode) else {
            continue;
        };
        match first_category {
            None => first_category = Some(cat),
            Some(first) if cat == first => {
                if crossed {
                    return false;
                }
            }
            Some(_) => {
                if !crossed && !slot_op_is_store(insn.opcode) {
                    return false;
                }
                crossed = true;
            }
        }
    }
    crossed
}

fn exception_value_conflicted_slots(
    insns: &[Instruction],
    exception_regions: &[ExceptionRegion],
) -> BTreeSet<u16> {
    exception_local_types(insns, exception_regions)
        .into_iter()
        .filter(|(_, ty): &(u16, String)| ty == "Object")
        .map(|(slot, _): (u16, String)| slot)
        .collect()
}

fn astore_target_slot(insn: &Instruction) -> Option<u16> {
    match (insn.opcode, &insn.operands) {
        (0x3A, Operands::Local(idx)) => Some(*idx),
        (0x4B..=0x4E, _) => Some(u16::from(insn.opcode - 0x4B)),
        _ => None,
    }
}

fn store_target_slot(insn: &Instruction) -> Option<u16> {
    match (insn.opcode, &insn.operands) {
        (0x36..=0x3A, Operands::Local(idx)) => Some(*idx),
        (0x3B..=0x3E, _) => Some(u16::from(insn.opcode - 0x3B)),
        (0x3F..=0x42, _) => Some(u16::from(insn.opcode - 0x3F)),
        (0x43..=0x46, _) => Some(u16::from(insn.opcode - 0x43)),
        (0x47..=0x4A, _) => Some(u16::from(insn.opcode - 0x47)),
        (0x4B..=0x4E, _) => Some(u16::from(insn.opcode - 0x4B)),
        _ => None,
    }
}

fn reused_exception_slots(
    insns: &[Instruction],
    exception_regions: &[ExceptionRegion],
) -> BTreeSet<u16> {
    let handler_pcs: BTreeSet<u32> = exception_regions.iter().map(|r| r.handler_pc).collect();
    let mut value_store_slots: BTreeSet<u16> = BTreeSet::new();
    for insn in insns {
        if handler_pcs.contains(&insn.pc) {
            continue;
        }
        if let Some(slot) = store_target_slot(insn) {
            value_store_slots.insert(slot);
        }
    }
    let mut out: BTreeSet<u16> = BTreeSet::new();
    for region in exception_regions {
        let Some(handler): Option<&Instruction> = insns
            .iter()
            .find(|i: &&Instruction| i.pc == region.handler_pc)
        else {
            continue;
        };
        let slot: Option<u16> = match (handler.opcode, &handler.operands) {
            (0x3A, Operands::Local(idx)) => Some(*idx),
            (0x4B..=0x4E, _) => Some(u16::from(handler.opcode - 0x4B)),
            _ => None,
        };
        if let Some(slot) = slot
            && value_store_slots.contains(&slot)
            && !handler_slot_read_as_value(insns, region.handler_pc, slot)
        {
            out.insert(slot);
        }
    }
    out
}

fn handler_slot_read_as_value(insns: &[Instruction], handler_pc: u32, slot: u16) -> bool {
    let start: usize = match insns.iter().position(|i: &Instruction| i.pc == handler_pc) {
        Some(p) => p + 1,
        None => return false,
    };
    for ins in &insns[start..] {
        let read_slot: Option<u16> = match (ins.opcode, &ins.operands) {
            (0x15..=0x19, Operands::Local(idx)) => Some(*idx),
            (0x1A..=0x1D, _) => Some(u16::from(ins.opcode - 0x1A)),
            (0x1E..=0x21, _) => Some(u16::from(ins.opcode - 0x1E)),
            (0x22..=0x25, _) => Some(u16::from(ins.opcode - 0x22)),
            (0x26..=0x29, _) => Some(u16::from(ins.opcode - 0x26)),
            (0x2A..=0x2D, _) => Some(u16::from(ins.opcode - 0x2A)),
            _ => None,
        };
        if read_slot == Some(slot) {
            return true;
        }
        let overwrites: bool = matches!(
            (ins.opcode, &ins.operands),
            (0x3A, Operands::Local(idx)) if *idx == slot
        ) || matches!(ins.opcode, 0x4B..=0x4E if u16::from(ins.opcode - 0x4B) == slot);
        if overwrites {
            return false;
        }
        if matches!(ins.opcode, 0xA7 | 0xC8 | 0xAC..=0xB1 | 0xBF | 0x99..=0xA6 | 0xC6 | 0xC7) {
            return false;
        }
    }
    false
}

fn ldc_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    match cf.constant_pool.get(usize::from(*idx)) {
        Some(crate::classfile::ConstantPoolEntry::String { .. }) => Some("String".to_string()),
        Some(crate::classfile::ConstantPoolEntry::Class { .. }) => Some("Class".to_string()),
        _ => None,
    }
}

fn new_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    cf.class_name(*idx)
        .ok()
        .map(|n: &str| descriptor::binary_to_source(n))
}

fn checkcast_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    cf.class_name(*idx)
        .ok()
        .map(|n: &str| descriptor::binary_to_source(n))
}

fn new_array_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    match (&insn.operands, insn.opcode) {
        (Operands::NewArray(code), _) => Some(format!("{}[]", primitive_array_type(*code))),
        (Operands::ConstPool(idx), 0xBD) => cf
            .class_name(*idx)
            .ok()
            .map(|n: &str| format!("{}[]", descriptor::binary_to_source(n))),
        _ => None,
    }
}

fn multi_new_array_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::MultiANewArray { index, .. } = &insn.operands else {
        return None;
    };
    let raw: String = bytecode::resolve_ref(cf, *index)?;
    Some(descriptor::binary_to_source(&raw))
}

fn field_static_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *idx)?;
    let (_owner, desc): (&str, &str) = reference.rsplit_once(':')?;
    let ty: JavaType = descriptor::parse_field(desc)?;
    reference_type_name(&ty)
}

fn invoke_return_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return None,
    };
    let reference: String = bytecode::resolve_ref(cf, idx)?;
    let (_member, desc): (&str, &str) = reference.rsplit_once(':')?;
    let parsed: MethodDescriptor = descriptor::parse_method(desc)?;
    if matches!(parsed.returns, JavaType::Void) {
        return Some("void".to_string());
    }
    reference_type_name(&parsed.returns)
}

fn invoke_dynamic_return_type(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let idx: u16 = match &insn.operands {
        Operands::InvokeDynamic(i) | Operands::ConstPool(i) => *i,
        _ => return None,
    };
    let crate::classfile::ConstantPoolEntry::InvokeDynamic {
        name_and_type_index,
        ..
    } = cf.constant_pool.get(usize::from(idx))?
    else {
        return None;
    };
    let (_name, desc): (String, String) = name_and_type_parts(cf, *name_and_type_index)?;
    let parsed: MethodDescriptor = descriptor::parse_method(&desc)?;
    if matches!(parsed.returns, JavaType::Void) {
        return Some("void".to_string());
    }
    reference_type_name(&parsed.returns)
}

fn invoke_dynamic_pop_count(cf: &ClassFile, insn: &Instruction) -> usize {
    let idx: u16 = match &insn.operands {
        Operands::InvokeDynamic(i) | Operands::ConstPool(i) => *i,
        _ => return 0,
    };
    let Some(crate::classfile::ConstantPoolEntry::InvokeDynamic {
        name_and_type_index,
        ..
    }) = cf.constant_pool.get(usize::from(idx))
    else {
        return 0;
    };
    name_and_type_parts(cf, *name_and_type_index)
        .and_then(|(_, d): (String, String)| descriptor::parse_method(&d))
        .map_or(0, |m: MethodDescriptor| m.params.len())
}

fn invoke_pop_count(cf: &ClassFile, insn: &Instruction, op: u8) -> usize {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return 0,
    };
    let argc: usize = bytecode::resolve_ref(cf, idx)
        .and_then(|r: String| {
            r.rsplit_once(':')
                .and_then(|(_, d): (&str, &str)| descriptor::parse_method(d))
                .map(|m: MethodDescriptor| m.params.len())
        })
        .unwrap_or(0);
    if op == 0xB8 { argc } else { argc + 1 }
}

fn reference_type_name(ty: &JavaType) -> Option<String> {
    match ty {
        JavaType::Object(_) | JavaType::Array(_) => {
            let rendered: String = ty.render();
            if rendered == "Object" {
                None
            } else {
                Some(rendered)
            }
        }
        _ => None,
    }
}

struct RenderCtx<'a> {
    cf: &'a ClassFile,
    cfg: &'a Cfg,
    insns: &'a [Instruction],
    params: &'a [(u16, String)],
    bootstraps: &'a [crate::attributes::BootstrapMethod],
    rendered_blocks: BTreeSet<BlockId>,
    fully_lifted: bool,
    block_entry_stacks: BTreeMap<BlockId, Vec<Expr>>,
    has_this: bool,
    bool_return: bool,
    pending_handler_seed: Option<(BlockId, Vec<Expr>)>,
    handler_entry_skips: BTreeSet<BlockId>,
    finally_catch_parameter_slots: BTreeSet<u16>,
    finally_scoped_local_slots: BTreeSet<u16>,
    declared_finally_scoped_local_slots: BTreeSet<u16>,
    pattern_binding_slots: BTreeSet<u16>,
    catch_var_counter: usize,
    reused_exc_slots: BTreeSet<u16>,
    bool_array_names: BTreeMap<String, u8>,
    string_switch_tables: BTreeMap<BlockId, crate::decompile_struct::StringSwitchTable>,
    slot_types: BTreeMap<u16, String>,
    param_types: BTreeMap<u16, String>,
    foreach_suppress_slots: BTreeSet<u16>,
    foreach_hidden_slots: BTreeSet<u16>,
    finally_inline_skips: BTreeMap<BlockId, usize>,
    finally_tail_trims: BTreeMap<BlockId, usize>,
    finally_return_stores: BTreeMap<BlockId, u16>,
}

fn indent_string(level: usize) -> String {
    "    ".repeat(level)
}

const MAX_RENDER_BYTES: usize = 4 * 1024 * 1024;

fn collect_continue_latches(region: &Region, latches: &mut BTreeSet<BlockId>) {
    match region {
        Region::Sequence(items) => {
            for item in items {
                collect_continue_latches(item, latches);
            }
        }
        Region::IfThen { then_body, .. } => collect_continue_latches(then_body, latches),
        Region::IfThenElse {
            then_body,
            else_body,
            ..
        } => {
            collect_continue_latches(then_body, latches);
            collect_continue_latches(else_body, latches);
        }
        Region::Try { try_body, handlers } => {
            collect_continue_latches(try_body, latches);
            for (_, handler) in handlers {
                collect_continue_latches(handler, latches);
            }
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_body,
            ..
        } => {
            collect_continue_latches(try_body, latches);
            for (_, handler) in handlers {
                collect_continue_latches(handler, latches);
            }
            collect_continue_latches(finally_body, latches);
        }
        Region::Synchronized { body, .. }
        | Region::LabeledLoop { body, .. }
        | Region::TryWithResources { try_body: body, .. } => {
            collect_continue_latches(body, latches);
        }
        Region::Continue {
            label: None,
            latch: Some(latch),
        } => {
            latches.insert(*latch);
        }
        Region::Block(_)
        | Region::While { .. }
        | Region::DoWhile { .. }
        | Region::Switch { .. }
        | Region::Break { .. }
        | Region::Continue { .. }
        | Region::Irreducible { .. } => {}
    }
}

fn finally_continue_latch(
    ctx: &RenderCtx<'_>,
    region: &Region,
    header: BlockId,
) -> Option<BlockId> {
    let Region::Sequence(items) = region else {
        return None;
    };
    let mut latches: BTreeSet<BlockId> = BTreeSet::new();
    for item in items {
        if let Region::TryFinally { finally_body, .. } = item {
            collect_continue_latches(finally_body, &mut latches);
        }
    }
    let [latch]: [BlockId; 1] = latches
        .into_iter()
        .collect::<Vec<BlockId>>()
        .try_into()
        .ok()?;
    let terminal_uses_latch: bool = match items.last()? {
        Region::Continue {
            label: None,
            latch: Some(terminal_latch),
        } => *terminal_latch == latch,
        Region::Block(terminal_latch) => {
            *terminal_latch == latch
                && ctx
                    .cfg
                    .blocks
                    .get(terminal_latch.0 as usize)
                    .and_then(single_normal_successor)
                    == Some(header)
        }
        _ => false,
    };
    terminal_uses_latch.then_some(latch)
}

fn render_for_update(ctx: &RenderCtx<'_>, latch: BlockId) -> Option<String> {
    let mut rendered: String = String::new();
    render_latch_inline(ctx, latch, &mut rendered, 0);
    let trimmed: &str = rendered.trim();
    if trimmed.lines().count() != 1 {
        return None;
    }
    trimmed.strip_suffix(';').map(str::to_owned)
}

fn render_loop_body(
    ctx: &mut RenderCtx<'_>,
    body: &Region,
    update_latch: BlockId,
    out: &mut String,
    level: usize,
) {
    let Region::Sequence(items) = body else {
        render_region(ctx, body, out, level);
        return;
    };
    let end: usize = items.len().saturating_sub(usize::from(matches!(
        items.last(),
        Some(Region::Continue {
            label: None,
            latch: Some(latch)
        }) if *latch == update_latch
    )));
    for item in &items[..end] {
        render_region(ctx, item, out, level);
    }
}

fn render_region(ctx: &mut RenderCtx<'_>, region: &Region, out: &mut String, level: usize) {
    if out.len() > MAX_RENDER_BYTES {
        return;
    }
    match region {
        Region::Block(bid) => render_block(ctx, *bid, out, level),
        Region::Sequence(items) => {
            let mut i: usize = 0;
            while i < items.len() {
                if i + 1 < items.len()
                    && let Region::Block(pre) = &items[i]
                    && matches!(&items[i + 1], Region::While { .. })
                    && try_render_foreach(ctx, *pre, &items[i + 1], out, level)
                {
                    i += 2;
                    continue;
                }
                render_region(ctx, &items[i], out, level);
                i += 1;
            }
        }
        Region::IfThen {
            head,
            then_body,
            join,
            ..
        } => {
            if try_render_assert(ctx, *head, then_body, *join, out, level) {
                return;
            }
            let cond: String = render_if_condition(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(ctx, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::IfThenElse {
            head,
            then_body,
            else_body,
            join,
            ..
        } => {
            if try_render_conditional_expr(ctx, *head, then_body, else_body, *join, out, level) {
                return;
            }
            let cond: String = render_if_condition(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}if ({}) {{", invert(&cond));
            render_region(ctx, then_body, out, level + 1);
            let _ = writeln!(out, "{pad}}} else {{");
            render_region(ctx, else_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::While { header, body, exit } => {
            let cond: String = render_if_condition(ctx, *header, out, level);
            let negated: bool =
                matches!(exit, Some(e) if header_cond_true_target(ctx.cfg, *header) == Some(*e));
            let displayed_cond: String = if negated { invert(&cond) } else { cond };
            let pad: String = indent_string(level);
            let update: Option<(BlockId, String)> = finally_continue_latch(ctx, body, *header)
                .and_then(|latch: BlockId| {
                    render_for_update(ctx, latch).map(|s: String| (latch, s))
                });
            if let Some((latch, update)) = update {
                let _ = writeln!(out, "{pad}for (; {displayed_cond}; {update}) {{");
                ctx.rendered_blocks.insert(latch);
                render_loop_body(ctx, body, latch, out, level + 1);
            } else {
                let _ = writeln!(out, "{pad}while ({displayed_cond}) {{");
                render_region(ctx, body, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
            if let Some(exit_bid) = exit
                && ctx.rendered_blocks.contains(exit_bid)
                && let Some(stmt) = shared_terminal_tail_statement(ctx, *exit_bid)
            {
                let _ = writeln!(out, "{pad}{stmt}");
            }
        }
        Region::DoWhile { header, body, .. } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}do {{");
            render_block(ctx, *header, out, level + 1);
            render_region(ctx, body, out, level + 1);
            let _ = writeln!(out, "{pad}}} while (true);");
        }
        Region::Switch {
            head,
            cases,
            default,
            join,
        } => {
            if try_render_type_switch(ctx, *head, cases, default.as_deref(), *join, out, level) {
                return;
            }
            if let Some(table) = ctx.string_switch_tables.get(head).cloned() {
                render_string_switch(ctx, cases, default.as_deref(), &table, out, level);
                return;
            }
            if try_render_enum_switch(ctx, *head, cases, default.as_deref(), out, level) {
                return;
            }
            if try_render_value_switch(ctx, *head, cases, default.as_deref(), *join, out, level) {
                return;
            }
            if try_render_yield_switch(ctx, *head, cases, default.as_deref(), *join, out, level) {
                return;
            }
            let expr: String = render_switch_subject(ctx, *head, out, level);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}switch ({expr}) {{");
            for (i, (key, body)) in cases.iter().enumerate() {
                let label: String = format_switch_key(key, i);
                let _ = writeln!(out, "{pad}    case {label}:");
                render_region(ctx, body, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            if let Some(def) = default {
                let _ = writeln!(out, "{pad}    default:");
                render_region(ctx, def, out, level + 2);
                let _ = writeln!(out, "{pad}        break;");
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Try { try_body, handlers } => {
            if handlers.is_empty() {
                render_region(ctx, try_body, out, level);
                return;
            }
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(ctx, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let var: String = catch_parameter_slot(ctx, handler_region).map_or_else(
                    || {
                        let fallback: String = format!("ex{}", ctx.catch_var_counter);
                        ctx.catch_var_counter += 1;
                        fallback
                    },
                    |(handler, slot): (BlockId, u16)| {
                        ctx.handler_entry_skips.insert(handler);
                        ctx.pattern_binding_slots.insert(slot);
                        local_name(slot, ctx.params)
                    },
                );
                let _ = writeln!(out, "{pad}}} catch ({ty} {var}) {{");
                render_handler_region(ctx, handler_region, &var, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryFinally {
            try_body,
            handlers,
            finally_body,
            ..
        } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try {{");
            render_region(ctx, try_body, out, level + 1);
            for (catch_types, handler_region) in handlers {
                let ty: String = descriptor::catch_clause(catch_types);
                let var: String = catch_parameter_slot(ctx, handler_region).map_or_else(
                    || {
                        let fallback: String = format!("ex{}", ctx.catch_var_counter);
                        ctx.catch_var_counter += 1;
                        fallback
                    },
                    |(handler, slot): (BlockId, u16)| {
                        ctx.handler_entry_skips.insert(handler);
                        ctx.pattern_binding_slots.insert(slot);
                        local_name(slot, ctx.params)
                    },
                );
                let _ = writeln!(out, "{pad}}} catch ({ty} {var}) {{");
                render_handler_region(ctx, handler_region, &var, out, level + 1);
            }
            let _ = writeln!(out, "{pad}}} finally {{");
            render_region(ctx, finally_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::TryWithResources {
            resource_slot,
            try_body,
        } => {
            let resource: String = local_name(*resource_slot, ctx.params);
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}try ({resource}) {{");
            render_region(ctx, try_body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::Synchronized {
            lock_block,
            lock_slot,
            body,
        } => {
            ctx.rendered_blocks.insert(*lock_block);
            let lock_expr: String = lift_lock_expr(ctx, *lock_block)
                .map_or_else(|| local_name(*lock_slot, ctx.params), |e: Expr| e.render());
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}synchronized ({lock_expr}) {{");
            render_region(ctx, body, out, level + 1);
            let _ = writeln!(out, "{pad}}}");
        }
        Region::LabeledLoop { label, body } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}L{label}:");
            render_region(ctx, body, out, level);
        }
        Region::Break { label } => {
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}break L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}break;");
                }
            }
        }
        Region::Continue { label, latch } => {
            if let Some(latch_bid) = latch
                && !ctx.rendered_blocks.contains(latch_bid)
            {
                render_latch_inline(ctx, *latch_bid, out, level);
            }
            let pad: String = indent_string(level);
            match label {
                Some(l) => {
                    let _ = writeln!(out, "{pad}continue L{l};");
                }
                None => {
                    let _ = writeln!(out, "{pad}continue;");
                }
            }
        }
        Region::Irreducible { blocks } => {
            let pad: String = indent_string(level);
            let _ = writeln!(out, "{pad}/// irreducible region");
            for bid in blocks {
                render_block(ctx, *bid, out, level);
            }
            ctx.fully_lifted = false;
        }
    }
}

fn block_insn_range(ctx: &RenderCtx<'_>, bid: BlockId) -> (usize, usize) {
    let b: &BasicBlock = &ctx.cfg.blocks[bid.0 as usize];
    b.insn_range
}

fn leftmost_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Block(b) => Some(*b),
        Region::Sequence(items) => items.first().and_then(leftmost_block),
        Region::IfThen { head, .. }
        | Region::IfThenElse { head, .. }
        | Region::Switch { head, .. } => Some(*head),
        Region::While { header, .. } | Region::DoWhile { header, .. } => Some(*header),
        Region::Try { try_body, .. }
        | Region::TryFinally { try_body, .. }
        | Region::TryWithResources { try_body, .. } => leftmost_block(try_body),
        Region::Synchronized { lock_block, .. } => Some(*lock_block),
        Region::LabeledLoop { body, .. } => leftmost_block(body),
        Region::Break { .. } | Region::Continue { .. } => None,
        Region::Irreducible { blocks } => blocks.first().copied(),
    }
}

fn render_handler_region(
    ctx: &mut RenderCtx<'_>,
    region: &Region,
    exc_name: &str,
    out: &mut String,
    level: usize,
) {
    let first: Option<BlockId> = match region {
        Region::Block(b) => Some(*b),
        Region::Sequence(items) => items.first().and_then(|r| match r {
            Region::Block(b) => Some(*b),
            _ => None,
        }),
        _ => None,
    };
    let Some(first_bid): Option<BlockId> = first else {
        if let Some(target) = leftmost_block(region)
            && !ctx.rendered_blocks.contains(&target)
            && !ctx.handler_entry_skips.contains(&target)
        {
            ctx.pending_handler_seed = Some((target, vec![Expr::Local(exc_name.to_string())]));
        }
        render_region(ctx, region, out, level);
        ctx.pending_handler_seed = None;
        return;
    };
    if ctx.rendered_blocks.contains(&first_bid) {
        render_region(ctx, region, out, level);
        return;
    }
    let seed: Vec<Expr> = if ctx.handler_entry_skips.contains(&first_bid) {
        Vec::new()
    } else {
        vec![Expr::Local(exc_name.to_string())]
    };
    render_block_seeded(ctx, first_bid, out, level, seed);
    match region {
        Region::Block(_) => {}
        Region::Sequence(items) => {
            for r in &items[1..] {
                render_region(ctx, r, out, level);
            }
        }
        _ => {}
    }
}

fn catch_parameter_slot(ctx: &RenderCtx<'_>, region: &Region) -> Option<(BlockId, u16)> {
    let handler: BlockId = leftmost_block(region)?;
    let block: &BasicBlock = ctx.cfg.blocks.get(handler.0 as usize)?;
    if !ctx
        .cfg
        .exception_regions
        .iter()
        .any(|entry: &ExceptionRegion| {
            entry.handler_pc == block.start_pc && entry.catch_type.is_some()
        })
    {
        return None;
    }
    let instruction: &Instruction = ctx.insns.get(block.insn_range.0)?;
    let slot: u16 = astore_target_slot(instruction)?;
    ctx.finally_catch_parameter_slots
        .contains(&slot)
        .then_some((handler, slot))
}

fn render_block(ctx: &mut RenderCtx<'_>, bid: BlockId, out: &mut String, level: usize) {
    render_block_seeded(ctx, bid, out, level, Vec::new());
}

fn finally_scoped_local_statement(
    ctx: &mut RenderCtx<'_>,
    instruction: &Instruction,
    statement: String,
) -> String {
    let Some(slot): Option<u16> = matches!(instruction.opcode, 0x36..=0x4E)
        .then(|| local_slot_operand(instruction))
        .flatten()
    else {
        return statement;
    };
    if !ctx.finally_scoped_local_slots.contains(&slot) {
        return statement;
    }
    let Some(ty): Option<String> = ctx.slot_types.get(&slot).cloned() else {
        ctx.finally_scoped_local_slots.remove(&slot);
        return statement;
    };
    if !ctx.declared_finally_scoped_local_slots.insert(slot) {
        return statement;
    }
    format!("{ty} {statement}")
}

struct ForEachPlan {
    header: BlockId,
    elem_ty: String,
    elem_name: String,
    iterable: String,
    slots: BTreeSet<u16>,
}

fn foreach_suppressed_slot(ins: &Instruction) -> Option<u16> {
    if let Operands::Iinc { index, .. } = ins.operands {
        return Some(index);
    }
    if matches!(ins.opcode, 0x36..=0x4E) {
        return local_slot_operand(ins);
    }
    None
}

fn slot_touched(ins: &Instruction) -> Option<u16> {
    if let Operands::Iinc { index, .. } = ins.operands {
        return Some(index);
    }
    match ins.opcode {
        0x15..=0x19 | 0x1A..=0x2D | 0x36..=0x4E => local_slot_operand(ins),
        _ => None,
    }
}

fn aload_slot_of(ins: &Instruction) -> Option<u16> {
    matches!(ins.opcode, 0x19 | 0x2A..=0x2D)
        .then(|| local_slot_operand(ins))
        .flatten()
}

fn iload_slot_of(ins: &Instruction) -> Option<u16> {
    matches!(ins.opcode, 0x15 | 0x1A..=0x1D)
        .then(|| local_slot_operand(ins))
        .flatten()
}

fn invoke_name_desc(cf: &ClassFile, ins: &Instruction) -> Option<(String, String)> {
    let index: u16 = match &ins.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return None,
    };
    let full: String = bytecode::resolve_ref(cf, index)?;
    let (owner_name, desc): (&str, &str) = full.rsplit_once(':')?;
    let (_owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some((name.to_string(), desc.to_string()))
}

fn single_normal_successor(block: &BasicBlock) -> Option<BlockId> {
    let mut normal = block
        .successors
        .iter()
        .filter(|e| !matches!(e.kind, EdgeKind::Exception));
    let first: BlockId = normal.next()?.target;
    if normal.next().is_some() {
        return None;
    }
    Some(first)
}

fn count_slot_touches(ctx: &RenderCtx<'_>, slot: u16) -> usize {
    ctx.insns
        .iter()
        .filter(|ins: &&Instruction| slot_touched(ins) == Some(slot))
        .count()
}

fn slot_confined(ctx: &RenderCtx<'_>, slot: u16, loop_blocks: &BTreeSet<BlockId>) -> bool {
    for block in &ctx.cfg.blocks {
        if loop_blocks.contains(&block.id) {
            continue;
        }
        let (lo, hi): (usize, usize) = block.insn_range;
        if ctx.insns[lo..hi]
            .iter()
            .any(|ins: &Instruction| slot_touched(ins) == Some(slot))
        {
            return false;
        }
    }
    true
}

fn value_stored_to_slot(ctx: &RenderCtx<'_>, bid: BlockId, slot: u16) -> Option<Expr> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let mut stack: Vec<Expr> = ctx
        .block_entry_stacks
        .get(&bid)
        .cloned()
        .unwrap_or_default();
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            continue;
        }
        if op == 0xC2 || op == 0xC3 {
            stack.pop();
            continue;
        }
        if matches!(op, 0x36..=0x4E) && local_slot_operand(ins) == Some(slot) {
            return stack.last().cloned();
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed
            | LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_) => {}
            LiftResult::Unhandled => return None,
        }
    }
    None
}

fn analyze_foreach(
    ctx: &RenderCtx<'_>,
    pre: BlockId,
    while_region: &Region,
) -> Option<ForEachPlan> {
    let Region::While { header, body, .. } = while_region else {
        return None;
    };
    let Region::Block(body_first) = body.as_ref() else {
        return None;
    };
    let header: BlockId = *header;
    let body_first: BlockId = *body_first;
    let pre_block: &BasicBlock = &ctx.cfg.blocks[pre.0 as usize];
    if single_normal_successor(pre_block) != Some(header) {
        return None;
    }
    let mut loop_blocks: BTreeSet<BlockId> = BTreeSet::new();
    loop_blocks.insert(pre);
    loop_blocks.insert(header);
    loop_blocks.insert(body_first);
    iterator_foreach(ctx, pre, header, body_first, &loop_blocks)
        .or_else(|| array_foreach(ctx, pre, header, body_first, &loop_blocks))
}

fn iterator_foreach(
    ctx: &RenderCtx<'_>,
    pre: BlockId,
    header: BlockId,
    body_first: BlockId,
    loop_blocks: &BTreeSet<BlockId>,
) -> Option<ForEachPlan> {
    let (hlo, hhi): (usize, usize) = block_insn_range(ctx, header);
    let hins: &[Instruction] = &ctx.insns[hlo..hhi];
    if hins.len() != 3 || !matches!(hins[2].opcode, 0x99 | 0x9A) {
        return None;
    }
    let it_slot: u16 = aload_slot_of(&hins[0])?;
    let (name, desc): (String, String) = invoke_name_desc(ctx.cf, &hins[1])?;
    if name != "hasNext" || desc != "()Z" {
        return None;
    }
    let (blo, bhi): (usize, usize) = block_insn_range(ctx, body_first);
    let bins: &[Instruction] = &ctx.insns[blo..bhi];
    if bins.len() < 3 || aload_slot_of(&bins[0]) != Some(it_slot) {
        return None;
    }
    let (next_name, next_desc): (String, String) = invoke_name_desc(ctx.cf, &bins[1])?;
    if next_name != "next" || next_desc != "()Ljava/lang/Object;" {
        return None;
    }
    let store_idx: usize = if bins[2].opcode == 0xC0 { 3 } else { 2 };
    let store: &Instruction = bins.get(store_idx)?;
    if !matches!(store.opcode, 0x3A | 0x4B..=0x4E) {
        return None;
    }
    let elem_slot: u16 = local_slot_operand(store)?;
    if count_slot_touches(ctx, it_slot) != 3 || !slot_confined(ctx, elem_slot, loop_blocks) {
        return None;
    }
    let stored: Expr = value_stored_to_slot(ctx, pre, it_slot)?;
    let Expr::Invoke {
        receiver: Some(receiver),
        method,
        ..
    } = &stored
    else {
        return None;
    };
    if method != "iterator" {
        return None;
    }
    let mut elem_ty: String = ctx.slot_types.get(&elem_slot).cloned()?;
    if elem_ty == "Object"
        && let Some(source_type) = source_type_for_expr(ctx, receiver)
        && let Some(generic_element) = first_type_argument(&source_type)
    {
        elem_ty = generic_element;
    }
    let mut slots: BTreeSet<u16> = BTreeSet::new();
    slots.insert(it_slot);
    slots.insert(elem_slot);
    Some(ForEachPlan {
        header,
        elem_ty,
        elem_name: local_name(elem_slot, ctx.params),
        iterable: receiver.render(),
        slots,
    })
}

fn source_type_for_expr(ctx: &RenderCtx<'_>, expression: &Expr) -> Option<String> {
    let Expr::Local(name) = expression else {
        return None;
    };
    let slot: u16 = ctx
        .params
        .iter()
        .find_map(|(slot, parameter): &(u16, String)| (parameter == name).then_some(*slot))
        .or_else(|| name.strip_prefix("var")?.parse::<u16>().ok())?;
    ctx.param_types
        .get(&slot)
        .or_else(|| ctx.slot_types.get(&slot))
        .cloned()
}

fn first_type_argument(source_type: &str) -> Option<String> {
    let open: usize = source_type.find('<')?;
    let mut depth: usize = 0;
    let mut end: Option<usize> = None;
    for (offset, character) in source_type[open + 1..].char_indices() {
        match character {
            '<' => depth = depth.checked_add(1)?,
            '>' if depth == 0 => {
                end = Some(open + 1 + offset);
                break;
            }
            '>' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                end = Some(open + 1 + offset);
                break;
            }
            _ => {}
        }
    }
    let argument: &str = source_type.get(open + 1..end?)?.trim();
    if argument == "?" || argument.starts_with("? super ") {
        return None;
    }
    Some(
        argument
            .strip_prefix("? extends ")
            .unwrap_or(argument)
            .to_string(),
    )
}

fn array_foreach(
    ctx: &RenderCtx<'_>,
    pre: BlockId,
    header: BlockId,
    body_first: BlockId,
    loop_blocks: &BTreeSet<BlockId>,
) -> Option<ForEachPlan> {
    let (hlo, hhi): (usize, usize) = block_insn_range(ctx, header);
    let hins: &[Instruction] = &ctx.insns[hlo..hhi];
    if hins.len() != 3 || hins[2].opcode != 0xA2 {
        return None;
    }
    let idx_slot: u16 = iload_slot_of(&hins[0])?;
    let len_slot: u16 = iload_slot_of(&hins[1])?;
    let (blo, bhi): (usize, usize) = block_insn_range(ctx, body_first);
    let bins: &[Instruction] = &ctx.insns[blo..bhi];
    if bins.len() < 4
        || aload_slot_of(&bins[0]).is_none()
        || iload_slot_of(&bins[1]) != Some(idx_slot)
        || !matches!(bins[2].opcode, 0x2E..=0x35)
        || !matches!(bins[3].opcode, 0x36..=0x4E)
    {
        return None;
    }
    let arr_slot: u16 = aload_slot_of(&bins[0])?;
    let elem_slot: u16 = local_slot_operand(&bins[3])?;
    let mut slots: BTreeSet<u16> = BTreeSet::new();
    slots.extend([arr_slot, len_slot, idx_slot, elem_slot]);
    if slots.len() != 4
        || count_slot_touches(ctx, arr_slot) != 3
        || count_slot_touches(ctx, len_slot) != 2
        || count_slot_touches(ctx, idx_slot) != 4
        || !slot_confined(ctx, elem_slot, loop_blocks)
    {
        return None;
    }
    let stored: Expr = value_stored_to_slot(ctx, pre, arr_slot)?;
    let elem_ty: String = ctx.slot_types.get(&elem_slot).cloned()?;
    Some(ForEachPlan {
        header,
        elem_ty,
        elem_name: local_name(elem_slot, ctx.params),
        iterable: stored.render(),
        slots,
    })
}

fn try_render_foreach(
    ctx: &mut RenderCtx<'_>,
    pre: BlockId,
    while_region: &Region,
    out: &mut String,
    level: usize,
) -> bool {
    let Some(plan): Option<ForEachPlan> = analyze_foreach(ctx, pre, while_region) else {
        return false;
    };
    let Region::While { body, .. } = while_region else {
        return false;
    };
    let saved: BTreeSet<u16> =
        std::mem::replace(&mut ctx.foreach_suppress_slots, plan.slots.clone());
    render_block(ctx, pre, out, level);
    let pad: String = indent_string(level);
    let _ = writeln!(
        out,
        "{pad}for ({} {} : {}) {{",
        plan.elem_ty, plan.elem_name, plan.iterable
    );
    ctx.rendered_blocks.insert(plan.header);
    let mut rendered_body: String = String::new();
    render_region(ctx, body, &mut rendered_body, level + 1);
    if plan.elem_ty != "Object" {
        rendered_body = replace_java_code(
            &rendered_body,
            &format!("((Object) {})", plan.elem_name),
            &plan.elem_name,
        );
    }
    out.push_str(&rendered_body);
    let _ = writeln!(out, "{pad}}}");
    ctx.foreach_suppress_slots = saved;
    ctx.foreach_hidden_slots.extend(plan.slots);
    true
}

fn render_latch_inline(ctx: &RenderCtx<'_>, bid: BlockId, out: &mut String, level: usize) {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = ctx
        .block_entry_stacks
        .get(&bid)
        .cloned()
        .unwrap_or_default();
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9 | 0xC2 | 0xC3
        ) {
            continue;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
            }
            LiftResult::Pushed | LiftResult::Elided | LiftResult::Unhandled => {}
        }
    }
}

fn render_block_seeded(
    ctx: &mut RenderCtx<'_>,
    bid: BlockId,
    out: &mut String,
    level: usize,
    seed: Vec<Expr>,
) {
    if !ctx.rendered_blocks.insert(bid) {
        return;
    }
    let mut seed: Vec<Expr> = seed;
    if seed.is_empty()
        && let Some((target, pending)) = ctx.pending_handler_seed.take()
    {
        if target == bid {
            seed = pending;
        } else {
            ctx.pending_handler_seed = Some((target, pending));
        }
    }
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let end: usize = end
        .saturating_sub(ctx.finally_tail_trims.get(&bid).copied().unwrap_or(0))
        .max(start);
    let handler_entry_skip: usize = usize::from(ctx.handler_entry_skips.remove(&bid));
    let start: usize = start
        .saturating_add(ctx.finally_inline_skips.get(&bid).copied().unwrap_or(0))
        .saturating_add(handler_entry_skip)
        .min(end);
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = if seed.is_empty() {
        ctx.block_entry_stacks.get(&bid).cloned().unwrap_or(seed)
    } else {
        seed
    };
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            continue;
        }
        if op == 0xC3 {
            stack.pop();
            continue;
        }
        if op == 0xC2 {
            stack.pop();
            continue;
        }
        if let Some(astore_slot) = astore_target_slot(ins)
            && ctx.reused_exc_slots.contains(&astore_slot)
            && matches!(stack.last(), Some(Expr::Local(_)))
        {
            stack.pop();
            continue;
        }
        if !ctx.foreach_suppress_slots.is_empty()
            && let Some(slot) = foreach_suppressed_slot(ins)
            && ctx.foreach_suppress_slots.contains(&slot)
        {
            if op != 0x84 {
                stack.pop();
            }
            continue;
        }
        if op == 0x54
            && let Some(stmt) = boolean_array_store(&mut stack, &ctx.bool_array_names)
        {
            let _ = writeln!(out, "{pad}{stmt};");
            continue;
        }
        if matches!(op, 0x36 | 0x3B..=0x3E)
            && let Some(stmt) = boolean_local_store(ins, &mut stack, ctx.params, &ctx.slot_types)
        {
            let stmt: String = finally_scoped_local_statement(ctx, ins, stmt);
            let _ = writeln!(out, "{pad}{stmt};");
            continue;
        }
        if let Some(&ret_slot) = ctx.finally_return_stores.get(&bid)
            && matches!(op, 0x36..=0x4E)
            && local_slot_operand(ins) == Some(ret_slot)
        {
            let value: Option<Expr> = stack.pop();
            match value {
                Some(expr) => {
                    let _ = writeln!(out, "{pad}return {};", expr.render());
                }
                None => {
                    let _ = writeln!(out, "{pad}return;");
                }
            }
            continue;
        }
        let lifted: LiftResult = lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        );
        match lifted {
            LiftResult::Statement(s) => {
                let s: String = finally_scoped_local_statement(ctx, ins, s);
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
}

fn lift_lock_expr(ctx: &RenderCtx<'_>, bid: BlockId) -> Option<Expr> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let enter_idx: usize = slice.iter().position(|i: &Instruction| i.opcode == 0xC2)?;
    let dup_idx: usize = enter_idx.checked_sub(2)?;
    if slice.get(dup_idx)?.opcode != 0x59 {
        return None;
    }
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &slice[..dup_idx] {
        let op: u8 = ins.opcode;
        if matches!(op, 0xA7 | 0xC8) {
            continue;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_)
            | LiftResult::Unhandled => {
                return None;
            }
        }
    }
    if stack.len() == 1 { stack.pop() } else { None }
}

fn lift_block_to_value(ctx: &RenderCtx<'_>, bid: BlockId, seed_count: usize) -> Option<Expr> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(op, 0xA7 | 0xC8) {
            continue;
        }
        if matches!(op, 0x99..=0xA6 | 0xC6 | 0xC7 | 0xAA | 0xAB | 0xA9 | 0xAC..=0xB1 | 0xBF) {
            return None;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_)
            | LiftResult::Unhandled => {
                return None;
            }
        }
    }
    if stack.len() == seed_count + 1 {
        stack.pop()
    } else {
        None
    }
}

fn simulate_block(ctx: &RenderCtx<'_>, bid: BlockId, entry: &[Expr]) -> (Vec<Expr>, bool) {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let mut stack: Vec<Expr> = entry.to_vec();
    let mut clean: bool = true;
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            for _ in 0..branch_pop_count(op) {
                stack.pop();
            }
            continue;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed
            | LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_) => {}
            LiftResult::Unhandled => {
                stack.clear();
                clean = false;
            }
        }
    }
    let resolved: bool = stack.iter().all(|e: &Expr| !expr_has_hole(e));
    (stack, clean && resolved)
}

fn expr_has_hole(e: &Expr) -> bool {
    match e {
        Expr::Opaque(s) => s == HOLE_TOKEN,
        Expr::Const(_) | Expr::Local(_) | Expr::This | Expr::New(_) => false,
        Expr::StaticField { .. } => false,
        Expr::Field { receiver, .. } => expr_has_hole(receiver),
        Expr::Binary { lhs, rhs, .. } | Expr::Cmp { lhs, rhs } => {
            expr_has_hole(lhs) || expr_has_hole(rhs)
        }
        Expr::Unary { value, .. }
        | Expr::Cast { value, .. }
        | Expr::InstanceOf { value, .. }
        | Expr::ArrayLength(value)
        | Expr::NewArray { size: value, .. } => expr_has_hole(value),
        Expr::ArrayLoad { array, index } => expr_has_hole(array) || expr_has_hole(index),
        Expr::ArrayInit { elements, .. } => elements.iter().any(expr_has_hole),
        Expr::Invoke { receiver, args, .. } => {
            receiver.as_deref().is_some_and(expr_has_hole) || args.iter().any(expr_has_hole)
        }
    }
}

#[inline]
const fn branch_pop_count(op: u8) -> usize {
    match op {
        0x99..=0x9E | 0xC6 | 0xC7 | 0xAA | 0xAB => 1,
        0x9F..=0xA6 => 2,
        _ => 0,
    }
}

fn compute_block_entry_stacks(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> BTreeMap<BlockId, Vec<Expr>> {
    let probe: RenderCtx<'_> = RenderCtx {
        cf,
        cfg,
        insns,
        params,
        bootstraps,
        rendered_blocks: BTreeSet::new(),
        fully_lifted: true,
        block_entry_stacks: BTreeMap::new(),
        has_this,
        bool_return,
        pending_handler_seed: None,
        handler_entry_skips: BTreeSet::new(),
        finally_catch_parameter_slots: BTreeSet::new(),
        finally_scoped_local_slots: BTreeSet::new(),
        declared_finally_scoped_local_slots: BTreeSet::new(),
        pattern_binding_slots: BTreeSet::new(),
        catch_var_counter: 0,
        reused_exc_slots: BTreeSet::new(),
        bool_array_names: BTreeMap::new(),
        string_switch_tables: BTreeMap::new(),
        slot_types: BTreeMap::new(),
        param_types: BTreeMap::new(),
        foreach_suppress_slots: BTreeSet::new(),
        foreach_hidden_slots: BTreeSet::new(),
        finally_inline_skips: BTreeMap::new(),
        finally_tail_trims: BTreeMap::new(),
        finally_return_stores: BTreeMap::new(),
    };
    let dom: Dominators = compute_dominators(cfg);
    let mut exit_stacks: BTreeMap<BlockId, Vec<Expr>> = BTreeMap::new();
    let mut exit_clean: BTreeMap<BlockId, bool> = BTreeMap::new();
    let mut entry_stacks: BTreeMap<BlockId, Vec<Expr>> = BTreeMap::new();
    for bid in &dom.order {
        let block: &BasicBlock = &cfg.blocks[bid.0 as usize];
        let real_preds: Vec<BlockId> = block
            .predecessors
            .iter()
            .copied()
            .filter(|p: &BlockId| {
                cfg.blocks[p.0 as usize]
                    .successors
                    .iter()
                    .any(|e| e.target == *bid && !matches!(e.kind, EdgeKind::Exception))
            })
            .collect();
        let entry: Vec<Expr> = match real_preds.as_slice() {
            [single] if *single != *bid => {
                if exit_clean.get(single).copied().unwrap_or(false) {
                    exit_stacks.get(single).cloned().unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            preds if preds.len() >= 2 => agreed_join_entry(preds, *bid, &exit_stacks, &exit_clean)
                .or_else(|| bool_ternary_join_entry(&probe, *bid, preds, &exit_stacks, &exit_clean))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        if !entry.is_empty() {
            entry_stacks.insert(*bid, entry.clone());
        }
        let (exit, clean): (Vec<Expr>, bool) = simulate_block(&probe, *bid, &entry);
        exit_stacks.insert(*bid, exit);
        exit_clean.insert(*bid, clean);
    }
    entry_stacks
}

fn agreed_join_entry(
    preds: &[BlockId],
    bid: BlockId,
    exit_stacks: &BTreeMap<BlockId, Vec<Expr>>,
    exit_clean: &BTreeMap<BlockId, bool>,
) -> Option<Vec<Expr>> {
    let mut agreed: Option<Vec<Expr>> = None;
    for pred in preds {
        if *pred == bid || !exit_clean.get(pred).copied().unwrap_or(false) {
            return None;
        }
        let exit: &Vec<Expr> = exit_stacks.get(pred)?;
        if exit.is_empty() {
            return None;
        }
        match &agreed {
            None => agreed = Some(exit.clone()),
            Some(prev) if stacks_render_equal(prev, exit) => {}
            Some(_) => return None,
        }
    }
    agreed
}

fn bool_ternary_join_entry(
    ctx: &RenderCtx<'_>,
    bid: BlockId,
    preds: &[BlockId],
    exit_stacks: &BTreeMap<BlockId, Vec<Expr>>,
    exit_clean: &BTreeMap<BlockId, bool>,
) -> Option<Vec<Expr>> {
    let [a, b]: [BlockId; 2] = preds.try_into().ok()?;
    if a == bid || b == bid {
        return None;
    }
    if !exit_clean.get(&a).copied().unwrap_or(false)
        || !exit_clean.get(&b).copied().unwrap_or(false)
    {
        return None;
    }
    let ea: &Vec<Expr> = exit_stacks.get(&a)?;
    let eb: &Vec<Expr> = exit_stacks.get(&b)?;
    if ea.is_empty()
        || ea.len() != eb.len()
        || !stacks_render_equal(&ea[..ea.len() - 1], &eb[..eb.len() - 1])
    {
        return None;
    }
    let prefix_len: usize = ea.len() - 1;
    let (top_a, top_b): (&Expr, &Expr) = (&ea[prefix_len], &eb[prefix_len]);
    let (rendered_a, rendered_b): (String, String) = (top_a.render(), top_b.render());
    if rendered_a == rendered_b {
        return None;
    }
    let head: BlockId = sole_common_predecessor(ctx.cfg, a, b)?;
    let true_arm: BlockId = if head_true_target_is(ctx, head, a) {
        a
    } else if head_true_target_is(ctx, head, b) {
        b
    } else {
        return None;
    };
    let cond: String = head_condition_to(ctx, head, true_arm)?;
    let mut entry: Vec<Expr> = ea[..prefix_len].to_vec();
    if let ("1" | "0", "1" | "0") = (rendered_a.as_str(), rendered_b.as_str()) {
        let true_is_one: bool = if true_arm == a {
            rendered_a == "1"
        } else {
            rendered_b == "1"
        };
        entry.push(Expr::Opaque(if true_is_one { cond } else { invert(&cond) }));
        return Some(entry);
    }
    if expr_has_hole(top_a) || expr_has_hole(top_b) {
        return None;
    }
    if !arm_is_pure_value(ctx, a, prefix_len) || !arm_is_pure_value(ctx, b, prefix_len) {
        return None;
    }
    let (true_top, false_top): (&str, &str) = if true_arm == a {
        (&rendered_a, &rendered_b)
    } else {
        (&rendered_b, &rendered_a)
    };
    entry.push(Expr::Opaque(format!("({cond} ? {true_top} : {false_top})")));
    Some(entry)
}

fn head_true_target_is(ctx: &RenderCtx<'_>, head: BlockId, want: BlockId) -> bool {
    let block: &BasicBlock = &ctx.cfg.blocks[head.0 as usize];
    block
        .successors
        .iter()
        .any(|e| matches!(e.kind, EdgeKind::CondTrue | EdgeKind::CondFalse) && e.target == want)
}

fn arm_is_pure_value(ctx: &RenderCtx<'_>, bid: BlockId, prefix_len: usize) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let mut stack: Vec<Expr> = vec![Expr::This; prefix_len];
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(op, 0xA7 | 0xC8) {
            continue;
        }
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xAA | 0xAB | 0xA9 | 0xAC..=0xB1 | 0xBF
        ) {
            return false;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_)
            | LiftResult::Unhandled => {
                return false;
            }
        }
    }
    stack.len() == prefix_len + 1
}

fn sole_common_predecessor(cfg: &Cfg, a: BlockId, b: BlockId) -> Option<BlockId> {
    let preds_of = |bid: BlockId| -> BTreeSet<BlockId> {
        cfg.blocks[bid.0 as usize]
            .predecessors
            .iter()
            .copied()
            .filter(|p: &BlockId| {
                cfg.blocks[p.0 as usize]
                    .successors
                    .iter()
                    .any(|e| e.target == bid && !matches!(e.kind, EdgeKind::Exception))
            })
            .collect()
    };
    let common: Vec<BlockId> = preds_of(a).intersection(&preds_of(b)).copied().collect();
    match common.as_slice() {
        [single] => Some(*single),
        _ => None,
    }
}

fn head_condition_to(ctx: &RenderCtx<'_>, head: BlockId, want: BlockId) -> Option<String> {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    if end <= start {
        return None;
    }
    let term: &Instruction = ctx.insns.get(end - 1)?;
    if !matches!(term.opcode, 0x99..=0xA6 | 0xC6 | 0xC7) {
        return None;
    }
    let block: &BasicBlock = &ctx.cfg.blocks[head.0 as usize];
    let taken: BlockId = block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))?
        .target;
    let not_taken: BlockId = block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondFalse))?
        .target;
    if want != taken && want != not_taken {
        return None;
    }
    let mut stack: Vec<Expr> = ctx
        .block_entry_stacks
        .get(&head)
        .cloned()
        .unwrap_or_default();
    for ins in &ctx.insns[start..end - 1] {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed
            | LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_) => {}
            LiftResult::Unhandled => return None,
        }
    }
    if stack.iter().any(expr_has_hole) {
        return None;
    }
    let taken_cond: String = render_branch_condition(term, &mut stack, &ctx.bool_array_names);
    if want == taken {
        Some(taken_cond)
    } else {
        Some(invert(&taken_cond))
    }
}

fn stacks_render_equal(a: &[Expr], b: &[Expr]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y): (&Expr, &Expr)| x.render() == y.render())
}

fn single_block(region: &Region) -> Option<BlockId> {
    match region {
        Region::Block(b) => Some(*b),
        Region::Sequence(items) => match items.as_slice() {
            [Region::Block(b)] => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

fn try_render_conditional_expr(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    then_body: &Region,
    else_body: &Region,
    join: Option<BlockId>,
    out: &mut String,
    level: usize,
) -> bool {
    let Some(join_bid): Option<BlockId> = join else {
        return false;
    };
    let (Some(then_b), Some(else_b)): (Option<BlockId>, Option<BlockId>) =
        (single_block(then_body), single_block(else_body))
    else {
        return try_render_nested_conditional_expr(
            ctx, head, then_body, else_body, join_bid, out, level,
        );
    };
    if ctx.rendered_blocks.contains(&then_b)
        || ctx.rendered_blocks.contains(&else_b)
        || ctx.rendered_blocks.contains(&join_bid)
        || ctx.rendered_blocks.contains(&head)
    {
        return false;
    }
    let (Some(then_val), Some(else_val)): (Option<Expr>, Option<Expr>) = (
        lift_block_to_value(ctx, then_b, 0),
        lift_block_to_value(ctx, else_b, 0),
    ) else {
        return false;
    };
    if !join_consumes_one_value(ctx, join_bid) {
        return false;
    }
    let cond: String = render_head_prefix_and_condition(ctx, head, out, level);
    let displayed: String = invert(&cond);
    if let Some(boolean) = collapse_bool_ternary(ctx, join_bid, &displayed, &then_val, &else_val) {
        ctx.rendered_blocks.insert(then_b);
        ctx.rendered_blocks.insert(else_b);
        render_block_seeded(ctx, join_bid, out, level, vec![Expr::Opaque(boolean)]);
        return true;
    }
    if (expr_has_side_effect(&then_val) || expr_has_side_effect(&else_val))
        && join_seed_use_count(ctx, join_bid) > 1
    {
        return false;
    }
    let ternary: Expr = Expr::Opaque(format!(
        "({displayed} ? {} : {})",
        then_val.render(),
        else_val.render()
    ));
    ctx.rendered_blocks.insert(then_b);
    ctx.rendered_blocks.insert(else_b);
    render_block_seeded(ctx, join_bid, out, level, vec![ternary]);
    true
}

fn try_render_nested_conditional_expr(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    then_body: &Region,
    else_body: &Region,
    join_bid: BlockId,
    out: &mut String,
    level: usize,
) -> bool {
    if ctx.rendered_blocks.contains(&head) || ctx.rendered_blocks.contains(&join_bid) {
        return false;
    }
    if !join_consumes_one_value(ctx, join_bid) || join_seed_use_count(ctx, join_bid) > 1 {
        return false;
    }
    let mut consumed: Vec<BlockId> = Vec::new();
    let Some(then_val): Option<Expr> =
        lift_nested_conditional_value(ctx, then_body, join_bid, &mut consumed)
    else {
        return false;
    };
    let Some(else_val): Option<Expr> =
        lift_nested_conditional_value(ctx, else_body, join_bid, &mut consumed)
    else {
        return false;
    };
    if consumed
        .iter()
        .any(|bid: &BlockId| ctx.rendered_blocks.contains(bid))
    {
        return false;
    }
    let cond: String = render_head_prefix_and_condition(ctx, head, out, level);
    let displayed: String = invert(&cond);
    for bid in &consumed {
        ctx.rendered_blocks.insert(*bid);
    }
    let ternary: Expr = Expr::Opaque(format!(
        "({displayed} ? {} : {})",
        then_val.render(),
        else_val.render()
    ));
    render_block_seeded(ctx, join_bid, out, level, vec![ternary]);
    true
}

fn lift_nested_conditional_value(
    ctx: &RenderCtx<'_>,
    region: &Region,
    join_bid: BlockId,
    consumed: &mut Vec<BlockId>,
) -> Option<Expr> {
    if let Some(bid) = region_value_block(region, join_bid) {
        if bid == join_bid || ctx.rendered_blocks.contains(&bid) || consumed.contains(&bid) {
            return None;
        }
        let value: Expr = lift_block_to_value(ctx, bid, 0)?;
        if expr_has_hole(&value) {
            return None;
        }
        consumed.push(bid);
        return Some(value);
    }
    let Region::IfThenElse {
        head,
        then_body,
        else_body,
        ..
    } = region
    else {
        return None;
    };
    if ctx.rendered_blocks.contains(head) || consumed.contains(head) {
        return None;
    }
    let then_entry: BlockId = leftmost_block(then_body)?;
    let then_val: Expr = lift_nested_conditional_value(ctx, then_body, join_bid, consumed)?;
    let else_val: Expr = lift_nested_conditional_value(ctx, else_body, join_bid, consumed)?;
    let cond: String = head_condition_to(ctx, *head, then_entry)?;
    consumed.push(*head);
    Some(Expr::Opaque(format!(
        "({cond} ? {} : {})",
        then_val.render(),
        else_val.render()
    )))
}

fn collapse_bool_ternary(
    ctx: &RenderCtx<'_>,
    join_bid: BlockId,
    cond: &str,
    then_val: &Expr,
    else_val: &Expr,
) -> Option<String> {
    let (start, end): (usize, usize) = block_insn_range(ctx, join_bid);
    let body: &[Instruction] = ctx.insns.get(start..end)?;
    let first: &Instruction = body.first()?;
    let demands_boolean: bool = match first.opcode {
        0xAC => body.len() == 1 && ctx.bool_return,
        0xB3 | 0xB5 => join_field_is_boolean(ctx, first),
        _ => false,
    };
    if !demands_boolean {
        return None;
    }
    let then_lit: Option<&'static str> = int_literal_as_bool(&then_val.render());
    let else_lit: Option<&'static str> = int_literal_as_bool(&else_val.render());
    match (then_lit, else_lit) {
        (Some("true"), Some("false")) => Some(cond.to_string()),
        (Some("false"), Some("true")) => Some(invert(cond)),
        _ => None,
    }
}

fn join_field_is_boolean(ctx: &RenderCtx<'_>, store: &Instruction) -> bool {
    let Operands::ConstPool(idx) = &store.operands else {
        return false;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(ctx.cf, *idx) else {
        return false;
    };
    let Some((_owner, _name, desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return false;
    };
    matches!(descriptor::parse_field(&desc), Some(JavaType::Boolean))
}

fn render_head_prefix_and_condition(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (block_start, block_end): (usize, usize) = block_insn_range(ctx, head);
    let end: usize = block_end
        .saturating_sub(ctx.finally_tail_trims.get(&head).copied().unwrap_or(0))
        .max(block_start);
    let start: usize = block_start
        .saturating_add(ctx.finally_inline_skips.get(&head).copied().unwrap_or(0))
        .min(end);
    if start == end {
        ctx.rendered_blocks.insert(head);
        return "true".to_string();
    }
    let body_end: usize = end - 1;
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = ctx
        .block_entry_stacks
        .get(&head)
        .cloned()
        .unwrap_or_default();
    ctx.rendered_blocks.insert(head);
    for ins in &ctx.insns[start..body_end] {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
    let term: &Instruction = &ctx.insns[body_end];
    render_branch_condition(term, &mut stack, &ctx.bool_array_names)
}

fn expr_has_side_effect(expr: &Expr) -> bool {
    match expr {
        Expr::Invoke { .. } | Expr::New(_) | Expr::NewArray { .. } | Expr::ArrayInit { .. } => true,
        Expr::Cast { value, .. } => expr_has_side_effect(value),
        Expr::Binary { lhs, rhs, .. } => expr_has_side_effect(lhs) || expr_has_side_effect(rhs),
        Expr::ArrayLoad { array, index } => {
            expr_has_side_effect(array) || expr_has_side_effect(index)
        }
        _ => false,
    }
}

fn join_seed_use_count(ctx: &RenderCtx<'_>, bid: BlockId) -> usize {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let sentinel: &str = "\u{0}__SEED__\u{0}";
    let mut stack: Vec<Expr> = vec![Expr::Opaque(sentinel.to_string())];
    let mut uses: usize = 0;
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(
            op,
            0x99..=0xA6 | 0xC6 | 0xC7 | 0xA7 | 0xC8 | 0xAA | 0xAB | 0xA9
        ) {
            continue;
        }
        let before: usize = stack
            .iter()
            .filter(|e| matches!(e, Expr::Opaque(s) if s == sentinel))
            .count();
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed
            | LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_) => {}
            LiftResult::Unhandled => break,
        }
        let after: usize = stack
            .iter()
            .filter(|e| matches!(e, Expr::Opaque(s) if s == sentinel))
            .count();
        if after > before {
            uses += after - before;
        }
    }
    uses.max(1)
}

fn join_consumes_one_value(ctx: &RenderCtx<'_>, bid: BlockId) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let Some(first): Option<&Instruction> = ctx.insns.get(start..end).and_then(|s| s.first())
    else {
        return false;
    };
    matches!(
        first.opcode,
        0xAC..=0xB0 | 0x36..=0x4E | 0xB3 | 0xB5 | 0x57
    )
}

fn render_if_condition(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (block_start, block_end): (usize, usize) = block_insn_range(ctx, head);
    let end: usize = block_end
        .saturating_sub(ctx.finally_tail_trims.get(&head).copied().unwrap_or(0))
        .max(block_start);
    let start: usize = block_start
        .saturating_add(ctx.finally_inline_skips.get(&head).copied().unwrap_or(0))
        .min(end);
    if start == end {
        return "true".to_string();
    }
    let body_end: usize = end - 1;
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = match ctx.pending_handler_seed.take() {
        Some((target, pending)) if target == head => pending,
        other => {
            ctx.pending_handler_seed = other;
            Vec::new()
        }
    };
    let already_rendered: bool = !ctx.rendered_blocks.insert(head);
    for ins in &ctx.insns[start..body_end] {
        let lifted: LiftResult = lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        );
        if already_rendered {
            continue;
        }
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
    let term: &Instruction = &ctx.insns[body_end];
    render_branch_condition(term, &mut stack, &ctx.bool_array_names)
}

fn render_branch_condition(
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    bool_arrays: &BTreeMap<String, u8>,
) -> String {
    match insn.opcode {
        0x99 => unary_or_cmp_cond(stack, "==", "== 0", bool_arrays),
        0x9A => unary_or_cmp_cond(stack, "!=", "!= 0", bool_arrays),
        0x9B => unary_or_cmp_cond(stack, "<", "< 0", bool_arrays),
        0x9C => unary_or_cmp_cond(stack, ">=", ">= 0", bool_arrays),
        0x9D => unary_or_cmp_cond(stack, ">", "> 0", bool_arrays),
        0x9E => unary_or_cmp_cond(stack, "<=", "<= 0", bool_arrays),
        0x9F | 0xA5 => binary_cond_kept(stack, "=="),
        0xA0 | 0xA6 => binary_cond_kept(stack, "!="),
        0xA1 => binary_cond_kept(stack, "<"),
        0xA2 => binary_cond_kept(stack, ">="),
        0xA3 => binary_cond_kept(stack, ">"),
        0xA4 => binary_cond_kept(stack, "<="),
        0xC6 => unary_cond_kept(stack, "== null"),
        0xC7 => unary_cond_kept(stack, "!= null"),
        _ => "true".to_string(),
    }
}

fn unary_cond_kept(stack: &mut Vec<Expr>, suffix: &str) -> String {
    let v: Expr = pop_expr(stack);
    format!("{} {suffix}", v.render())
}

fn unary_or_cmp_cond(
    stack: &mut Vec<Expr>,
    rel_op: &str,
    zero_suffix: &str,
    bool_arrays: &BTreeMap<String, u8>,
) -> String {
    let v: Expr = pop_expr(stack);
    if zero_suffix == "== 0" || zero_suffix == "!= 0" {
        if let Some(rendered) = boolean_array_load_render(&v, zero_suffix == "== 0", bool_arrays) {
            return rendered;
        }
        if v.is_boolean() {
            let rendered: String = v.render();
            return if zero_suffix == "== 0" {
                format!("!({rendered})")
            } else {
                rendered
            };
        }
    }
    match v {
        Expr::Cmp { lhs, rhs } => format!("{} {rel_op} {}", lhs.render(), rhs.render()),
        other => format!("{} {zero_suffix}", other.render()),
    }
}

fn binary_cond_kept(stack: &mut Vec<Expr>, op: &str) -> String {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    format!("{} {op} {}", lhs.render(), rhs.render())
}

fn render_switch_subject(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    out: &mut String,
    level: usize,
) -> String {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    let end: usize = end
        .saturating_sub(ctx.finally_tail_trims.get(&head).copied().unwrap_or(0))
        .max(start);
    let start: usize = start
        .saturating_add(ctx.finally_inline_skips.get(&head).copied().unwrap_or(0))
        .min(end);
    if start == end {
        return "expr".to_string();
    }
    let body_end: usize = end - 1;
    let pad: String = indent_string(level);
    let mut stack: Vec<Expr> = Vec::new();
    let already_rendered: bool = !ctx.rendered_blocks.insert(head);
    for ins in &ctx.insns[start..body_end] {
        let lifted: LiftResult = lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        );
        if already_rendered {
            continue;
        }
        match lifted {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
                ctx.fully_lifted = false;
            }
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Unhandled => {
                stack.clear();
                ctx.fully_lifted = false;
                let _ = writeln!(out, "{pad}// {} (stack reset)", ins.mnemonic);
            }
        }
    }
    pop_expr(&mut stack).render()
}

fn object_local_slot(insn: &Instruction) -> Option<u16> {
    match (insn.opcode, &insn.operands) {
        (0x19 | 0x3A, Operands::Local(idx)) => Some(*idx),
        (0x2A..=0x2D, _) => Some(u16::from(insn.opcode - 0x2A)),
        (0x4B..=0x4E, _) => Some(u16::from(insn.opcode - 0x4B)),
        _ => None,
    }
}

fn head_is_type_switch(ctx: &RenderCtx<'_>, head: BlockId) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    ctx.insns[start..end]
        .iter()
        .any(|ins: &Instruction| type_switch_indy_name(ctx.cf, ins, ctx.bootstraps).is_some())
}

fn type_switch_indy_name(
    cf: &ClassFile,
    insn: &Instruction,
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> Option<()> {
    let Operands::InvokeDynamic(idx) = &insn.operands else {
        return None;
    };
    let crate::classfile::ConstantPoolEntry::InvokeDynamic {
        bootstrap_method_attr_index,
        ..
    } = cf.constant_pool.get(usize::from(*idx))?
    else {
        return None;
    };
    let bsm: &crate::attributes::BootstrapMethod =
        bootstraps.get(usize::from(*bootstrap_method_attr_index))?;
    let name: String = method_handle_ref_name(cf, bsm.method_ref_index)?;
    (name == "typeSwitch").then_some(())
}

struct TypeSwitchArm {
    ty: String,
    var: String,
    slot: u16,
    value: Expr,
}

fn try_render_type_switch(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    cases: &[(SwitchKey, Region)],
    default: Option<&Region>,
    join: Option<BlockId>,
    out: &mut String,
    level: usize,
) -> bool {
    if !head_is_type_switch(ctx, head) {
        return false;
    }
    let Some(join_bid): Option<BlockId> = join else {
        return false;
    };
    if ctx.rendered_blocks.contains(&head) || ctx.rendered_blocks.contains(&join_bid) {
        return false;
    }
    let Some(subject): Option<Expr> = type_switch_subject(ctx, head) else {
        return false;
    };
    let head_start_pc: u32 = ctx.cfg.blocks[head.0 as usize].start_pc;

    let mut arms: Vec<TypeSwitchArm> = Vec::with_capacity(cases.len());
    let mut case_blocks: Vec<BlockId> = Vec::with_capacity(cases.len());
    for (_key, body) in cases {
        let Some(bid): Option<BlockId> = single_block(body) else {
            return false;
        };
        if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
            return false;
        }
        let Some(arm): Option<TypeSwitchArm> = lift_type_switch_arm(ctx, bid) else {
            return false;
        };
        arms.push(arm);
        case_blocks.push(bid);
    }

    let default_block: Option<BlockId> = match default {
        Some(region) => match single_block(region) {
            Some(bid) => Some(bid),
            None => return false,
        },
        None => None,
    };
    let default_arm: Option<String> = match default_block {
        Some(bid) => {
            if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
                return false;
            }
            if block_throws_match_exception(ctx, bid) {
                Some("throw new MatchException(null, null)".to_string())
            } else {
                let Some(value): Option<Expr> = lift_default_arm(ctx, bid) else {
                    return false;
                };
                Some(value.render())
            }
        }
        None => None,
    };

    let pad: String = indent_string(level);
    let inner: String = indent_string(level + 1);
    let mut switch_src: String = format!("switch ({}) {{\n", subject.render());
    for arm in &arms {
        ctx.pattern_binding_slots.insert(arm.slot);
        let _ = writeln!(
            switch_src,
            "{inner}case {} {} -> ({});",
            arm.ty,
            arm.var,
            arm.value.render()
        );
    }
    if let Some(def) = &default_arm {
        let _ = writeln!(switch_src, "{inner}default -> ({def});");
    }
    let _ = write!(switch_src, "{pad}}}");

    ctx.rendered_blocks.insert(head);
    for bid in &case_blocks {
        ctx.rendered_blocks.insert(*bid);
    }
    if let Some(bid) = default_block {
        ctx.rendered_blocks.insert(bid);
    }
    render_block_seeded(ctx, join_bid, out, level, vec![Expr::Opaque(switch_src)]);
    true
}

fn head_ends_in_int_switch(ctx: &RenderCtx<'_>, head: BlockId) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    ctx.insns
        .get(start..end)
        .and_then(<[Instruction]>::last)
        .is_some_and(|ins: &Instruction| {
            matches!(
                ins.operands,
                Operands::TableSwitch { .. } | Operands::LookupSwitch { .. }
            )
        })
}

struct ValueSwitchArm {
    block: BlockId,
    value: Expr,
}

fn region_value_block(region: &Region, join_bid: BlockId) -> Option<BlockId> {
    match region {
        Region::Block(b) => Some(*b),
        Region::Sequence(items) => match items.as_slice() {
            [Region::Block(b)] => Some(*b),
            [Region::Block(b), Region::Block(tail)] if *tail == join_bid => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

fn lift_value_switch_default(
    ctx: &RenderCtx<'_>,
    region: &Region,
    head_start_pc: u32,
    join_bid: BlockId,
) -> Option<(String, Vec<BlockId>)> {
    if let Some(bid) = region_value_block(region, join_bid) {
        if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
            return None;
        }
        let value: Expr = lift_block_to_value(ctx, bid, 0)?;
        if expr_has_hole(&value) {
            return None;
        }
        return Some((value.render(), vec![bid]));
    }
    let Region::IfThenElse {
        head: cond_head,
        then_body,
        else_body,
        ..
    } = region
    else {
        return None;
    };
    let (Some(then_b), Some(else_b)): (Option<BlockId>, Option<BlockId>) = (
        region_value_block(then_body, join_bid),
        region_value_block(else_body, join_bid),
    ) else {
        return None;
    };
    for bid in [*cond_head, then_b, else_b] {
        if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
            return None;
        }
    }
    let (Some(then_val), Some(else_val)): (Option<Expr>, Option<Expr>) = (
        lift_block_to_value(ctx, then_b, 0),
        lift_block_to_value(ctx, else_b, 0),
    ) else {
        return None;
    };
    if expr_has_hole(&then_val) || expr_has_hole(&else_val) {
        return None;
    }
    let cond: String = head_condition_to(ctx, *cond_head, then_b)?;
    let ternary: String = format!("{cond} ? {} : {}", then_val.render(), else_val.render());
    Some((ternary, vec![*cond_head, then_b, else_b]))
}

fn try_render_value_switch(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    cases: &[(SwitchKey, Region)],
    default: Option<&Region>,
    join: Option<BlockId>,
    out: &mut String,
    level: usize,
) -> bool {
    if cases.is_empty() || !head_ends_in_int_switch(ctx, head) {
        return false;
    }
    let Some(join_bid): Option<BlockId> = join else {
        return false;
    };
    if ctx.rendered_blocks.contains(&head) || ctx.rendered_blocks.contains(&join_bid) {
        return false;
    }
    if !join_consumes_one_value(ctx, join_bid) {
        return false;
    }
    let head_start_pc: u32 = ctx.cfg.blocks[head.0 as usize].start_pc;

    let mut arms: Vec<(String, ValueSwitchArm)> = Vec::with_capacity(cases.len());
    for (i, (key, body)) in cases.iter().enumerate() {
        let Some(bid): Option<BlockId> = single_block(body) else {
            return false;
        };
        if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
            return false;
        }
        let Some(value): Option<Expr> = lift_block_to_value(ctx, bid, 0) else {
            return false;
        };
        if expr_has_hole(&value) {
            return false;
        }
        let label: String = format_switch_key(key, i);
        arms.push((label, ValueSwitchArm { block: bid, value }));
    }

    let (default_src, default_blocks): (Option<String>, Vec<BlockId>) = match default {
        Some(region) => {
            let Some((src, blocks)): Option<(String, Vec<BlockId>)> =
                lift_value_switch_default(ctx, region, head_start_pc, join_bid)
            else {
                return false;
            };
            (Some(src), blocks)
        }
        None => (None, Vec::new()),
    };

    let subject: String = render_switch_subject(ctx, head, out, level);
    let pad: String = indent_string(level);
    let inner: String = indent_string(level + 1);
    let mut switch_src: String = format!("switch ({subject}) {{\n");
    for (label, arm) in &arms {
        let _ = writeln!(switch_src, "{inner}case {label} -> {};", arm.value.render());
    }
    if let Some(def) = &default_src {
        let _ = writeln!(switch_src, "{inner}default -> {def};");
    }
    let _ = write!(switch_src, "{pad}}}");

    for (_label, arm) in &arms {
        ctx.rendered_blocks.insert(arm.block);
    }
    for bid in &default_blocks {
        ctx.rendered_blocks.insert(*bid);
    }
    render_block_seeded(ctx, join_bid, out, level, vec![Expr::Opaque(switch_src)]);
    true
}

struct YieldSwitchArm {
    block: BlockId,
    label: String,
    stmts: String,
    value: Expr,
}

fn lift_switch_arm_body(
    ctx: &RenderCtx<'_>,
    bid: BlockId,
    body_level: usize,
) -> Option<(String, Expr)> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let mut stack: Vec<Expr> = Vec::new();
    let mut stmts: String = String::new();
    let pad: String = indent_string(body_level);
    for ins in &ctx.insns[start..end] {
        let op: u8 = ins.opcode;
        if matches!(op, 0xA7 | 0xC8) {
            continue;
        }
        if matches!(op, 0x99..=0xA6 | 0xC6 | 0xC7 | 0xAA | 0xAB | 0xA9 | 0xAC..=0xB1 | 0xBF) {
            return None;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed | LiftResult::Elided => {}
            LiftResult::Statement(s) => {
                let _ = writeln!(stmts, "{pad}{s};");
            }
            LiftResult::ControlFlow(_) | LiftResult::Unhandled => return None,
        }
    }
    if stack.len() != 1 {
        return None;
    }
    let value: Expr = stack.pop()?;
    if expr_has_hole(&value) || stmts.contains(HOLE_RENDER) {
        return None;
    }
    Some((stmts, value))
}

fn write_yield_arm(out: &mut String, selector: &str, stmts: &str, value: &Expr, level: usize) {
    let inner: String = indent_string(level + 1);
    if stmts.is_empty() {
        let _ = writeln!(out, "{inner}{selector} -> {};", value.render());
        return;
    }
    let arm_inner: String = indent_string(level + 2);
    let _ = writeln!(out, "{inner}{selector} -> {{");
    out.push_str(stmts);
    let _ = writeln!(out, "{arm_inner}yield {};", value.render());
    let _ = writeln!(out, "{inner}}}");
}

fn try_render_yield_switch(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    cases: &[(SwitchKey, Region)],
    default: Option<&Region>,
    join: Option<BlockId>,
    out: &mut String,
    level: usize,
) -> bool {
    if cases.is_empty() || !head_ends_in_int_switch(ctx, head) {
        return false;
    }
    let Some(join_bid): Option<BlockId> = join else {
        return false;
    };
    let Some(default_region): Option<&Region> = default else {
        return false;
    };
    if ctx.rendered_blocks.contains(&head) || ctx.rendered_blocks.contains(&join_bid) {
        return false;
    }
    if !join_consumes_one_value(ctx, join_bid) {
        return false;
    }
    let head_start_pc: u32 = ctx.cfg.blocks[head.0 as usize].start_pc;

    let mut arms: Vec<YieldSwitchArm> = Vec::with_capacity(cases.len());
    let mut has_block_arm: bool = false;
    for (i, (key, body)) in cases.iter().enumerate() {
        let Some(bid): Option<BlockId> = single_block(body) else {
            return false;
        };
        if ctx.rendered_blocks.contains(&bid) || block_branches_to_pc(ctx, bid, head_start_pc) {
            return false;
        }
        let Some((stmts, value)): Option<(String, Expr)> =
            lift_switch_arm_body(ctx, bid, level + 2)
        else {
            return false;
        };
        has_block_arm |= !stmts.is_empty();
        arms.push(YieldSwitchArm {
            block: bid,
            label: format_switch_key(key, i),
            stmts,
            value,
        });
    }

    let Some(default_bid): Option<BlockId> = single_block(default_region) else {
        return false;
    };
    if ctx.rendered_blocks.contains(&default_bid)
        || block_branches_to_pc(ctx, default_bid, head_start_pc)
    {
        return false;
    }
    let Some((default_stmts, default_value)): Option<(String, Expr)> =
        lift_switch_arm_body(ctx, default_bid, level + 2)
    else {
        return false;
    };
    has_block_arm |= !default_stmts.is_empty();
    if !has_block_arm {
        return false;
    }

    let subject: String = render_switch_subject(ctx, head, out, level);
    let pad: String = indent_string(level);
    let mut switch_src: String = format!("switch ({subject}) {{\n");
    for arm in &arms {
        write_yield_arm(
            &mut switch_src,
            &format!("case {}", arm.label),
            &arm.stmts,
            &arm.value,
            level,
        );
    }
    write_yield_arm(
        &mut switch_src,
        "default",
        &default_stmts,
        &default_value,
        level,
    );
    let _ = write!(switch_src, "{pad}}}");

    for arm in &arms {
        ctx.rendered_blocks.insert(arm.block);
    }
    ctx.rendered_blocks.insert(default_bid);
    render_block_seeded(ctx, join_bid, out, level, vec![Expr::Opaque(switch_src)]);
    true
}

fn switch_key_ints(key: &SwitchKey) -> Vec<i32> {
    match key {
        SwitchKey::Range { low, high } => (*low..=*high).collect(),
        SwitchKey::Values(vs) => vs.clone(),
    }
}

fn body_completes_normally(body_text: &str) -> bool {
    let Some(line): Option<&str> = body_text
        .lines()
        .rev()
        .find(|l: &&str| !l.trim().is_empty())
    else {
        return true;
    };
    let trimmed: &str = line.trim();
    !(trimmed.starts_with("return")
        || trimmed.starts_with("throw ")
        || trimmed == "throw"
        || trimmed.starts_with("break")
        || trimmed.starts_with("continue"))
}

fn render_switch_case_body(ctx: &mut RenderCtx<'_>, body: &Region, out: &mut String, level: usize) {
    let mut body_text: String = String::new();
    render_region(ctx, body, &mut body_text, level + 2);
    out.push_str(&body_text);
    if body_completes_normally(&body_text) {
        let pad: String = indent_string(level + 2);
        let _ = writeln!(out, "{pad}break;");
    }
}

enum EnumSwitchLabels {
    Direct { enum_internal: String },
    SwitchMap { field_ref: String },
}

fn enum_switch_subject(ctx: &RenderCtx<'_>, head: BlockId) -> Option<(Expr, EnumSwitchLabels)> {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let last: &Instruction = slice.last()?;
    if !matches!(
        last.operands,
        Operands::TableSwitch { .. } | Operands::LookupSwitch { .. }
    ) {
        return None;
    }
    let ord_pos: usize = slice
        .iter()
        .position(|ins: &Instruction| is_ordinal_invoke(ctx.cf, ins))?;
    let owner: String = ordinal_owner_internal(ctx.cf, &slice[ord_pos])?;
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &slice[..ord_pos] {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            _ => return None,
        }
    }
    let subject: Expr = stack.pop()?;
    if expr_has_hole(&subject) {
        return None;
    }
    let switchmap_ref: Option<String> = slice[..ord_pos]
        .iter()
        .find_map(|ins: &Instruction| switchmap_field_ref(ctx.cf, ins));
    let labels: EnumSwitchLabels = match switchmap_ref {
        Some(field_ref) => EnumSwitchLabels::SwitchMap { field_ref },
        None => EnumSwitchLabels::Direct {
            enum_internal: owner,
        },
    };
    Some((subject, labels))
}

fn enum_case_labels(key: &SwitchKey, labels: &EnumSwitchLabels) -> Option<Vec<String>> {
    switch_key_ints(key)
        .into_iter()
        .map(|k: i32| match labels {
            EnumSwitchLabels::Direct { enum_internal } => enum_constant_name(enum_internal, k),
            EnumSwitchLabels::SwitchMap { field_ref } => switchmap_label(field_ref, k),
        })
        .collect()
}

fn try_render_enum_switch(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    cases: &[(SwitchKey, Region)],
    default: Option<&Region>,
    out: &mut String,
    level: usize,
) -> bool {
    if ctx.rendered_blocks.contains(&head) {
        return false;
    }
    let Some((subject, labels)): Option<(Expr, EnumSwitchLabels)> = enum_switch_subject(ctx, head)
    else {
        return false;
    };
    let mut label_groups: Vec<Vec<String>> = Vec::with_capacity(cases.len());
    for (key, _body) in cases {
        let Some(names): Option<Vec<String>> = enum_case_labels(key, &labels) else {
            return false;
        };
        label_groups.push(names);
    }
    ctx.rendered_blocks.insert(head);
    let pad: String = indent_string(level);
    let _ = writeln!(out, "{pad}switch ({}) {{", subject.render());
    for ((_key, body), names) in cases.iter().zip(&label_groups) {
        for name in names {
            let _ = writeln!(out, "{pad}    case {name}:");
        }
        render_switch_case_body(ctx, body, out, level);
    }
    if let Some(def) = default {
        let _ = writeln!(out, "{pad}    default:");
        render_switch_case_body(ctx, def, out, level);
    }
    let _ = writeln!(out, "{pad}}}");
    true
}

fn render_string_switch(
    ctx: &mut RenderCtx<'_>,
    cases: &[(SwitchKey, Region)],
    default: Option<&Region>,
    table: &crate::decompile_struct::StringSwitchTable,
    out: &mut String,
    level: usize,
) {
    ctx.rendered_blocks.insert(table.prefix_block);
    for &bucket in &table.bucket_blocks {
        ctx.rendered_blocks.insert(bucket);
    }
    ctx.rendered_blocks.insert(table.idx_switch_head);
    let pad: String = indent_string(level);
    let (start, _end): (usize, usize) = block_insn_range(ctx, table.prefix_block);
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &ctx.insns[start..start + table.prefix_len] {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Statement(s) => {
                let _ = writeln!(out, "{pad}{s};");
            }
            LiftResult::ControlFlow(s) => {
                let _ = writeln!(out, "{pad}{s}");
            }
            LiftResult::Pushed | LiftResult::Elided | LiftResult::Unhandled => {}
        }
    }
    let subject: String = local_name(table.subject_source_slot, ctx.params);
    let _ = writeln!(out, "{pad}switch ({subject}) {{");
    for (key, body) in cases {
        for k in switch_key_ints(key) {
            let label: String = table
                .idx_to_literal
                .get(&k)
                .cloned()
                .unwrap_or_else(|| k.to_string());
            let _ = writeln!(out, "{pad}    case {label}:");
        }
        render_switch_case_body(ctx, body, out, level);
    }
    if let Some(def) = default {
        let _ = writeln!(out, "{pad}    default:");
        render_switch_case_body(ctx, def, out, level);
    }
    let _ = writeln!(out, "{pad}}}");
}

fn is_assertions_disabled_getstatic(cf: &ClassFile, insn: &Instruction) -> bool {
    let Operands::ConstPool(idx) = &insn.operands else {
        return false;
    };
    bytecode::resolve_ref(cf, *idx).is_some_and(|reference: String| {
        reference
            .rsplit_once(':')
            .is_some_and(|(member, desc): (&str, &str)| {
                member.ends_with(".$assertionsDisabled") && desc == "Z"
            })
    })
}

fn is_new_assertion_error(cf: &ClassFile, insn: &Instruction) -> bool {
    if insn.opcode != 0xBB {
        return false;
    }
    let Operands::ConstPool(idx) = &insn.operands else {
        return false;
    };
    bytecode::resolve_ref(cf, *idx).as_deref() == Some("java/lang/AssertionError")
}

fn assertion_error_init_arity(cf: &ClassFile, insn: &Instruction) -> Option<usize> {
    if insn.opcode != 0xB7 {
        return None;
    }
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *idx)?;
    let (member, desc): (&str, &str) = reference.rsplit_once(':')?;
    if member != "java/lang/AssertionError.<init>" {
        return None;
    }
    descriptor::parse_method(desc).map(|m: MethodDescriptor| m.params.len())
}

fn cond_edge_targets(block: &BasicBlock) -> (Option<BlockId>, Option<BlockId>) {
    let mut cond_true: Option<BlockId> = None;
    let mut cond_false: Option<BlockId> = None;
    for edge in &block.successors {
        match edge.kind {
            EdgeKind::CondTrue => cond_true = Some(edge.target),
            EdgeKind::CondFalse => cond_false = Some(edge.target),
            _ => {}
        }
    }
    (cond_true, cond_false)
}

fn region_is_assertion_throw(ctx: &RenderCtx<'_>, region: &Region) -> Option<BlockId> {
    let bid: BlockId = single_block(region)?;
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let has_new: bool = slice
        .iter()
        .any(|ins: &Instruction| is_new_assertion_error(ctx.cf, ins));
    let ends_throw: bool = slice
        .last()
        .is_some_and(|ins: &Instruction| ins.opcode == 0xBF);
    (has_new && ends_throw).then_some(bid)
}

enum AssertThrow {
    NoDetail,
    Detail(String),
}

fn assertion_error_detail(ctx: &RenderCtx<'_>, throw_bid: BlockId) -> Option<AssertThrow> {
    let (start, end): (usize, usize) = block_insn_range(ctx, throw_bid);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let new_pos: usize = slice
        .iter()
        .position(|ins: &Instruction| is_new_assertion_error(ctx.cf, ins))?;
    let (init_pos, arity): (usize, usize) =
        slice
            .iter()
            .enumerate()
            .find_map(|(i, ins): (usize, &Instruction)| {
                assertion_error_init_arity(ctx.cf, ins).map(|a: usize| (i, a))
            })?;
    if arity == 0 {
        return Some(AssertThrow::NoDetail);
    }
    let detail_slice: &[Instruction] = slice.get(new_pos + 2..init_pos)?;
    let value: Expr = lift_value_slice(ctx, detail_slice)?;
    Some(AssertThrow::Detail(value.render()))
}

fn assert_condition_via_cfg(
    ctx: &RenderCtx<'_>,
    cond_head: BlockId,
    throw_entry: BlockId,
) -> Option<String> {
    let (start, end): (usize, usize) = block_insn_range(ctx, cond_head);
    if start >= end {
        return None;
    }
    let mut stack: Vec<Expr> = Vec::new();
    for ins in &ctx.insns[start..end - 1] {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            _ => return None,
        }
    }
    let raw: String =
        render_branch_condition(&ctx.insns[end - 1], &mut stack, &ctx.bool_array_names);
    let block: &BasicBlock = &ctx.cfg.blocks[cond_head.0 as usize];
    let (cond_true, cond_false): (Option<BlockId>, Option<BlockId>) = cond_edge_targets(block);
    if cond_true == Some(throw_entry) {
        Some(invert(&raw))
    } else if cond_false == Some(throw_entry) {
        Some(raw)
    } else {
        None
    }
}

fn try_render_assert(
    ctx: &mut RenderCtx<'_>,
    head: BlockId,
    then_body: &Region,
    join: Option<BlockId>,
    out: &mut String,
    level: usize,
) -> bool {
    if ctx.rendered_blocks.contains(&head) {
        return false;
    }
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    let Some([guard, branch]): Option<&[Instruction; 2]> = ctx
        .insns
        .get(start..end)
        .and_then(|s: &[Instruction]| s.try_into().ok())
    else {
        return false;
    };
    if !is_assertions_disabled_getstatic(ctx.cf, guard) || !matches!(branch.opcode, 0x99 | 0x9A) {
        return false;
    }
    let (cond_head, throw_region, rest_region): (BlockId, &Region, Option<&Region>) =
        match then_body {
            Region::IfThenElse {
                head,
                then_body,
                else_body,
                ..
            } => {
                if region_is_assertion_throw(ctx, then_body).is_some() {
                    (*head, then_body.as_ref(), Some(else_body.as_ref()))
                } else if region_is_assertion_throw(ctx, else_body).is_some() {
                    (*head, else_body.as_ref(), Some(then_body.as_ref()))
                } else {
                    return false;
                }
            }
            Region::IfThen {
                head, then_body, ..
            } if region_is_assertion_throw(ctx, then_body).is_some() => {
                (*head, then_body.as_ref(), None)
            }
            _ => return false,
        };
    let Some(throw_bid): Option<BlockId> = region_is_assertion_throw(ctx, throw_region) else {
        return false;
    };
    let Some(detail): Option<AssertThrow> = assertion_error_detail(ctx, throw_bid) else {
        return false;
    };
    let Some(condition): Option<String> = assert_condition_via_cfg(ctx, cond_head, throw_bid)
    else {
        return false;
    };
    let _ = join;
    ctx.rendered_blocks.insert(head);
    ctx.rendered_blocks.insert(cond_head);
    ctx.rendered_blocks.insert(throw_bid);
    let pad: String = indent_string(level);
    match detail {
        AssertThrow::Detail(message) => {
            let _ = writeln!(out, "{pad}assert {condition} : {message};");
        }
        AssertThrow::NoDetail => {
            let _ = writeln!(out, "{pad}assert {condition};");
        }
    }
    if let Some(rest) = rest_region {
        render_region(ctx, rest, out, level);
    }
    true
}

fn type_switch_subject(ctx: &RenderCtx<'_>, head: BlockId) -> Option<Expr> {
    let (start, end): (usize, usize) = block_insn_range(ctx, head);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let indy_pos: usize = slice.iter().position(|ins: &Instruction| {
        type_switch_indy_name(ctx.cf, ins, ctx.bootstraps).is_some()
    })?;
    let aload: &Instruction = slice.get(indy_pos.checked_sub(2)?)?;
    let slot: u16 = object_local_slot(aload)?;
    if slot == 0 && !ctx.params.iter().any(|(i, _): &(u16, String)| *i == 0) {
        return Some(Expr::This);
    }
    Some(Expr::Local(local_name(slot, ctx.params)))
}

fn aload_source_slot(insn: &Instruction) -> Option<u16> {
    match (insn.opcode, &insn.operands) {
        (0x19, Operands::Local(idx)) => Some(*idx),
        (0x2A..=0x2D, _) => Some(u16::from(insn.opcode - 0x2A)),
        _ => None,
    }
}

fn is_require_non_null(cf: &ClassFile, insn: &Instruction) -> bool {
    if insn.opcode != 0xB8 {
        return false;
    }
    let Operands::ConstPool(idx) = insn.operands else {
        return false;
    };
    bytecode::resolve_ref(cf, idx).is_some_and(|r: String| r.contains("requireNonNull"))
}

fn selector_source_slot(cf: &ClassFile, insns: &[Instruction], selector_slot: u16) -> Option<u16> {
    let store_idx: usize = insns
        .iter()
        .position(|ins: &Instruction| astore_target_slot(ins) == Some(selector_slot))?;
    let mut probe: usize = store_idx.checked_sub(1)?;
    loop {
        let insn: &Instruction = insns.get(probe)?;
        match insn.opcode {
            0x57 | 0x59 => {
                probe = probe.checked_sub(1)?;
            }
            0xB8 if is_require_non_null(cf, insn) => {
                probe = probe.checked_sub(1)?;
            }
            _ => break,
        }
    }
    aload_source_slot(insns.get(probe)?)
}

fn type_switch_restart_slot(insns: &[Instruction], dispatch_idx: usize) -> Option<u16> {
    let iload: &Instruction = insns.get(dispatch_idx.checked_sub(1)?)?;
    match (iload.opcode, &iload.operands) {
        (0x15, Operands::Local(idx)) => Some(*idx),
        (0x1A..=0x1D, _) => Some(u16::from(iload.opcode - 0x1A)),
        _ => None,
    }
}

fn resolve_subject_to_param(
    cf: &ClassFile,
    insns: &[Instruction],
    selector_slot: u16,
    params: &[(u16, String)],
    has_this: bool,
) -> Option<Expr> {
    if params
        .iter()
        .any(|(i, _): &(u16, String)| *i == selector_slot)
    {
        return None;
    }
    let src: u16 = selector_source_slot(cf, insns, selector_slot)?;
    if src == 0 && has_this && !params.iter().any(|(i, _): &(u16, String)| *i == 0) {
        return Some(Expr::This);
    }
    params
        .iter()
        .any(|(i, _): &(u16, String)| *i == src)
        .then(|| Expr::Local(local_name(src, params)))
}

fn block_branches_to_pc(ctx: &RenderCtx<'_>, bid: BlockId, target_pc: u32) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    branch_targets(&ctx.insns[start..end]).contains(&target_pc)
}

fn lift_type_switch_arm(ctx: &RenderCtx<'_>, bid: BlockId) -> Option<TypeSwitchArm> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let cast_pos: usize = slice
        .iter()
        .position(|ins: &Instruction| ins.opcode == 0xC0)?;
    let cast_insn: &Instruction = &slice[cast_pos];
    let Operands::ConstPool(cp_idx) = &cast_insn.operands else {
        return None;
    };
    let ty: String =
        bytecode::resolve_ref(ctx.cf, *cp_idx).map(|n: String| descriptor::binary_to_source(&n))?;
    let store_insn: &Instruction = slice.get(cast_pos + 1)?;
    let slot: u16 = object_local_slot(store_insn)?;
    let var: String = local_name(slot, ctx.params);
    let body_value: Expr = lift_value_slice(ctx, &slice[cast_pos + 2..])?;
    Some(TypeSwitchArm {
        ty,
        var,
        slot,
        value: body_value,
    })
}

fn lift_default_arm(ctx: &RenderCtx<'_>, bid: BlockId) -> Option<Expr> {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    lift_value_slice(ctx, &ctx.insns[start..end])
}

fn block_throws_match_exception(ctx: &RenderCtx<'_>, bid: BlockId) -> bool {
    let (start, end): (usize, usize) = block_insn_range(ctx, bid);
    let slice: &[Instruction] = &ctx.insns[start..end];
    let throws: bool = slice
        .last()
        .is_some_and(|ins: &Instruction| ins.opcode == 0xBF);
    let news_match: bool = slice.iter().any(|ins: &Instruction| {
        ins.opcode == 0xBB
            && matches!(&ins.operands, Operands::ConstPool(i)
                if bytecode::resolve_ref(ctx.cf, *i).as_deref() == Some("java/lang/MatchException"))
    });
    throws && news_match
}

fn lift_value_slice(ctx: &RenderCtx<'_>, slice: &[Instruction]) -> Option<Expr> {
    let mut stack: Vec<Expr> = Vec::new();
    for ins in slice {
        let op: u8 = ins.opcode;
        if matches!(op, 0xA7 | 0xC8 | 0xAC..=0xB1) {
            continue;
        }
        if op == 0xBA {
            fold_make_concat_arm(ctx, ins, &mut stack)?;
            continue;
        }
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            LiftResult::Elided
            | LiftResult::Statement(_)
            | LiftResult::ControlFlow(_)
            | LiftResult::Unhandled => {
                return None;
            }
        }
    }
    if stack.len() != 1 {
        return None;
    }
    let value: Expr = stack.pop()?;
    (!expr_has_hole(&value)).then_some(value)
}

struct PatternArm {
    label: String,
    guard: Option<String>,
    body: String,
    binding_slots: Vec<u16>,
}

#[derive(Clone)]
struct RecordComponent {
    ty: String,
    name: String,
    slot: u16,
}

fn abs_target(pc: u32, offset: i32) -> u32 {
    (i64::from(pc) + i64::from(offset)) as u32
}

fn insn_index_at_pc(insns: &[Instruction], pc: u32) -> Option<usize> {
    insns
        .binary_search_by_key(&pc, |ins: &Instruction| ins.pc)
        .ok()
}

fn class_ref_at(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    bytecode::resolve_ref(cf, *idx)
}

fn is_match_exception_default(insns: &[Instruction], from: usize) -> bool {
    insns
        .get(from..)
        .into_iter()
        .flatten()
        .take_while(|ins: &&Instruction| ins.opcode != 0xA7)
        .any(|ins: &Instruction| ins.opcode == 0xBF)
        && insns[from..]
            .iter()
            .take(6)
            .any(|ins: &Instruction| ins.opcode == 0xBB)
}

struct SwitchTargets {
    cases: Vec<(i32, u32)>,
    default_pc: u32,
}

fn switch_targets(switch_insn: &Instruction) -> Option<SwitchTargets> {
    match &switch_insn.operands {
        Operands::TableSwitch {
            default,
            low,
            offsets,
            ..
        } => {
            let cases: Vec<(i32, u32)> = offsets
                .iter()
                .enumerate()
                .map(|(i, off): (usize, &i32)| (*low + i as i32, abs_target(switch_insn.pc, *off)))
                .collect();
            Some(SwitchTargets {
                cases,
                default_pc: abs_target(switch_insn.pc, *default),
            })
        }
        Operands::LookupSwitch { default, pairs } => {
            let cases: Vec<(i32, u32)> = pairs
                .iter()
                .map(|(key, off): &(i32, i32)| (*key, abs_target(switch_insn.pc, *off)))
                .collect();
            Some(SwitchTargets {
                cases,
                default_pc: abs_target(switch_insn.pc, *default),
            })
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn try_reconstruct_pattern_method(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> Option<MethodBody> {
    let dispatch_idx: usize = insns
        .iter()
        .position(|ins: &Instruction| type_switch_indy_name(cf, ins, bootstraps).is_some())?;
    let switch_insn: &Instruction = insns.get(dispatch_idx + 1)?;
    let targets: SwitchTargets = switch_targets(switch_insn)?;
    let selector_insn: &Instruction = insns.get(dispatch_idx.checked_sub(2)?)?;
    let selector_slot: u16 = object_local_slot(selector_insn)?;
    let resolved_subject: Option<Expr> =
        resolve_subject_to_param(cf, insns, selector_slot, params, has_this);
    let subject: Expr = match resolved_subject.clone() {
        Some(expr) => expr,
        None if selector_slot == 0 && !params.iter().any(|(i, _)| *i == 0) => Expr::This,
        None => Expr::Local(local_name(selector_slot, params)),
    };
    let dispatch_pc: u32 = insns.get(dispatch_idx.checked_sub(2)?)?.pc;
    let default_pc: u32 = targets.default_pc;

    let ctx: RenderCtx<'_> =
        pattern_render_ctx(cf, cfg, insns, params, bootstraps, has_this, bool_return);
    let mut arms: Vec<PatternArm> = Vec::with_capacity(targets.cases.len());
    let mut null_before_index: Option<i32> = None;
    for (case_value, arm_pc) in &targets.cases {
        if let Some(nested) = expand_record_arm(&ctx, insns, *arm_pc, dispatch_pc, default_pc) {
            arms.extend(nested);
            continue;
        }
        let arm: PatternArm = reconstruct_pattern_arm(
            &ctx,
            insns,
            *arm_pc,
            selector_slot,
            dispatch_pc,
            *case_value,
            0,
            &mut null_before_index,
        )?;
        arms.push(arm);
    }

    let default_idx: usize = insn_index_at_pc(insns, default_pc)?;
    let default_arm: Option<String> = if is_match_exception_default(insns, default_idx) {
        None
    } else {
        let end_pc: u32 = arm_end_pc(insns, default_idx);
        let slice: &[Instruction] = arm_slice(insns, default_idx, end_pc);
        Some(lift_value_slice(&ctx, slice)?.render())
    };

    let switch_src: String = render_pattern_switch(&subject, &arms, default_arm.as_deref());
    let mut binding_slots: BTreeSet<u16> = BTreeSet::new();
    for arm in &arms {
        for slot in &arm.binding_slots {
            binding_slots.insert(*slot);
        }
    }
    if resolved_subject.is_some() {
        binding_slots.insert(selector_slot);
        if let Some(restart_slot) = type_switch_restart_slot(insns, dispatch_idx) {
            binding_slots.insert(restart_slot);
        }
    }
    let decls: String = local_declarations(
        cf,
        insns,
        params,
        param_types,
        &cfg.exception_regions,
        &binding_slots,
    );
    Some(MethodBody {
        text: format!("{decls}        return {switch_src};\n"),
        fully_lifted: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn try_reconstruct_instanceof_deconstruction(
    cf: &ClassFile,
    cfg: &Cfg,
    insns: &[Instruction],
    params: &[(u16, String)],
    param_types: &BTreeMap<u16, String>,
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> Option<MethodBody> {
    let has_match_exception: bool = insns.iter().any(|ins: &Instruction| {
        ins.opcode == 0xBB
            && matches!(&ins.operands, Operands::ConstPool(i)
                if bytecode::resolve_ref(cf, *i).as_deref() == Some("java/lang/MatchException"))
    });
    if !has_match_exception {
        return None;
    }
    let instanceof_idx: usize = insns
        .iter()
        .position(|ins: &Instruction| ins.opcode == 0xC1)?;
    let subject_insn: &Instruction = insns.get(instanceof_idx.checked_sub(1)?)?;
    let subject_slot: u16 = object_local_slot(subject_insn)?;
    let subject: Expr = if subject_slot == 0 && !params.iter().any(|(i, _)| *i == 0) {
        Expr::This
    } else {
        Expr::Local(local_name(subject_slot, params))
    };
    let record_ty: String =
        descriptor::binary_to_source(&class_ref_at(cf, &insns[instanceof_idx])?);
    let branch_insn: &Instruction = insns.get(instanceof_idx + 1)?;
    if branch_insn.opcode != 0x99 {
        return None;
    }
    let else_pc: u32 = branch_abs(branch_insn)?;
    let bind_store: &Instruction = insns.get(instanceof_idx + 3)?;
    let record_slot: u16 = object_local_slot(bind_store)?;

    let ctx: RenderCtx<'_> =
        pattern_render_ctx(cf, cfg, insns, params, bootstraps, has_this, bool_return);
    let record: RecordDeconstruction =
        try_record_deconstruction(&ctx, insns, instanceof_idx + 4, record_slot, 0, else_pc)?;
    let then_body: String = lift_arm_body(&ctx, insns, record.body_idx)?;

    let else_idx: usize = insn_index_at_pc(insns, else_pc)?;
    let else_body: String = lift_arm_body(&ctx, insns, else_idx)?;

    let pattern: String = render_record_pattern(&record_ty, &record.components);
    let mut binding_slots: BTreeSet<u16> = record.components.iter().map(|c| c.slot).collect();
    binding_slots.insert(record_slot);
    let decls: String = local_declarations(
        cf,
        insns,
        params,
        param_types,
        &cfg.exception_regions,
        &binding_slots,
    );
    let body: String = format!(
        "        if ({} instanceof {pattern}) {{\n            return {then_body};\n        }}\n        return {else_body};\n",
        subject.render()
    );
    Some(MethodBody {
        text: format!("{decls}{body}"),
        fully_lifted: true,
    })
}

const fn pattern_render_ctx<'a>(
    cf: &'a ClassFile,
    cfg: &'a Cfg,
    insns: &'a [Instruction],
    params: &'a [(u16, String)],
    bootstraps: &'a [crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> RenderCtx<'a> {
    RenderCtx {
        cf,
        cfg,
        insns,
        params,
        bootstraps,
        rendered_blocks: BTreeSet::new(),
        fully_lifted: true,
        block_entry_stacks: BTreeMap::new(),
        has_this,
        bool_return,
        pending_handler_seed: None,
        handler_entry_skips: BTreeSet::new(),
        finally_catch_parameter_slots: BTreeSet::new(),
        finally_scoped_local_slots: BTreeSet::new(),
        declared_finally_scoped_local_slots: BTreeSet::new(),
        pattern_binding_slots: BTreeSet::new(),
        catch_var_counter: 0,
        reused_exc_slots: BTreeSet::new(),
        bool_array_names: BTreeMap::new(),
        string_switch_tables: BTreeMap::new(),
        slot_types: BTreeMap::new(),
        param_types: BTreeMap::new(),
        foreach_suppress_slots: BTreeSet::new(),
        foreach_hidden_slots: BTreeSet::new(),
        finally_inline_skips: BTreeMap::new(),
        finally_tail_trims: BTreeMap::new(),
        finally_return_stores: BTreeMap::new(),
    }
}

fn arm_end_pc(insns: &[Instruction], start_idx: usize) -> u32 {
    for ins in &insns[start_idx..] {
        if matches!(ins.opcode, 0xA7 | 0xC8 | 0xAC..=0xB1) {
            return ins.pc;
        }
    }
    insns
        .last()
        .map_or(u32::MAX, |ins: &Instruction| ins.pc + 1)
}

fn arm_slice(insns: &[Instruction], start_idx: usize, end_pc: u32) -> &[Instruction] {
    let end_idx: usize = insns[start_idx..]
        .iter()
        .position(|ins: &Instruction| ins.pc >= end_pc)
        .map_or(insns.len(), |rel: usize| start_idx + rel);
    &insns[start_idx..end_idx]
}

fn record_accessor_arity(record_binary: &str) -> Option<usize> {
    record_arity_for(record_binary)
}

fn infer_record_arity(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    idx: usize,
    record_slot: u16,
) -> Option<usize> {
    let mut count: usize = 0;
    let mut cursor: usize = idx;
    while count < RECORD_ARITY_PROBE_CAP {
        let accessor_load: &Instruction = insns.get(cursor)?;
        if object_local_slot(accessor_load) != Some(record_slot) {
            break;
        }
        let invoke: &Instruction = insns.get(cursor + 1)?;
        if invoke.opcode != 0xB6 && invoke.opcode != 0xB9 {
            break;
        }
        if invoke_method_name(ctx.cf, invoke).is_none() {
            break;
        }
        let store_tmp: &Instruction = insns.get(cursor + 2)?;
        let tmp_slot: u16 = object_local_slot(store_tmp)?;
        count += 1;
        if let Some(next) = probe_component_typeswitch(ctx, insns, cursor + 3, tmp_slot) {
            cursor = next;
        } else if let Some(next) = probe_component_inlined(insns, cursor + 3, tmp_slot) {
            cursor = next;
        } else {
            break;
        }
    }
    (count > 0).then_some(count)
}

fn probe_component_typeswitch(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    idx: usize,
    tmp_slot: u16,
) -> Option<usize> {
    let load_tmp: &Instruction = insns.get(idx + 2)?;
    if object_local_slot(load_tmp) != Some(tmp_slot) {
        return None;
    }
    let indy: &Instruction = insns.get(idx + 4)?;
    type_switch_indy_name(ctx.cf, indy, ctx.bootstraps)?;
    let switch_insn: &Instruction = insns.get(idx + 5)?;
    let targets: SwitchTargets = switch_targets(switch_insn)?;
    let first_case_pc: u32 = targets.cases.iter().map(|(_, pc): &(i32, u32)| *pc).min()?;
    let case_idx: usize = insn_index_at_pc(insns, first_case_pc)?;
    if insns
        .get(case_idx)
        .is_some_and(|i: &Instruction| i.opcode == 0xC0)
    {
        Some(case_idx + 2)
    } else if object_local_slot(insns.get(case_idx)?) == Some(tmp_slot)
        && insns
            .get(case_idx + 1)
            .is_some_and(|i: &Instruction| i.opcode == 0xC0)
    {
        Some(case_idx + 3)
    } else {
        None
    }
}

fn probe_component_inlined(insns: &[Instruction], idx: usize, tmp_slot: u16) -> Option<usize> {
    let load_tmp: &Instruction = insns.get(idx)?;
    if object_local_slot(load_tmp) != Some(tmp_slot) {
        return None;
    }
    if insns.get(idx + 1)?.opcode != 0xC1 {
        return None;
    }
    if insns.get(idx + 2)?.opcode != 0x99 {
        return None;
    }
    if insns.get(idx + 4)?.opcode != 0xC0 {
        return None;
    }
    let goto: &Instruction = insns.get(idx + 6)?;
    let body_pc: u32 = if goto.opcode == 0xA7 {
        branch_abs(goto)?
    } else {
        goto.pc
    };
    insn_index_at_pc(insns, body_pc)
}

fn expand_record_arm(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    arm_pc: u32,
    parent_dispatch_pc: u32,
    parent_default_pc: u32,
) -> Option<Vec<PatternArm>> {
    let start_idx: usize = insn_index_at_pc(insns, arm_pc)?;
    let cast: &Instruction = insns.get(start_idx + 1)?;
    if cast.opcode != 0xC0 {
        return None;
    }
    let record_binary: String = class_ref_at(ctx.cf, cast)?;
    let record_ty: String = descriptor::binary_to_source(&record_binary);
    let store: &Instruction = insns.get(start_idx + 2)?;
    let record_slot: u16 = object_local_slot(store)?;
    let arity: usize = match record_accessor_arity(&record_binary) {
        Some(known) => known,
        None => infer_record_arity(ctx, insns, start_idx + 3, record_slot)?,
    };
    let mut binding_slots: Vec<u16> = vec![record_slot];
    let arms: Vec<PatternArm> = walk_record_components(
        ctx,
        insns,
        start_idx + 3,
        record_slot,
        &record_ty,
        arity,
        Vec::new(),
        parent_dispatch_pc,
        parent_default_pc,
        &mut binding_slots,
    )?;
    Some(arms)
}

#[allow(clippy::too_many_arguments)]
fn walk_record_components(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    idx: usize,
    record_slot: u16,
    record_ty: &str,
    arity: usize,
    bound: Vec<RecordComponent>,
    parent_dispatch_pc: u32,
    parent_default_pc: u32,
    binding_slots: &mut Vec<u16>,
) -> Option<Vec<PatternArm>> {
    if bound.len() == arity {
        let pattern: String = render_record_pattern(record_ty, &bound);
        let body: String = lift_arm_body(ctx, insns, idx)?;
        for component in &bound {
            binding_slots.push(component.slot);
        }
        return Some(vec![PatternArm {
            label: pattern,
            guard: None,
            body,
            binding_slots: binding_slots.clone(),
        }]);
    }

    let accessor_load: &Instruction = insns.get(idx)?;
    if object_local_slot(accessor_load) != Some(record_slot) {
        return None;
    }
    let invoke: &Instruction = insns.get(idx + 1)?;
    if invoke.opcode != 0xB6 && invoke.opcode != 0xB9 {
        return None;
    }
    invoke_method_name(ctx.cf, invoke)?;
    let store_tmp: &Instruction = insns.get(idx + 2)?;
    let tmp_slot: u16 = object_local_slot(store_tmp)?;

    if let Some(arms) = walk_component_typeswitch(
        ctx,
        insns,
        idx + 3,
        record_slot,
        record_ty,
        arity,
        &bound,
        tmp_slot,
        binding_slots,
    ) {
        return Some(arms);
    }

    walk_component_inlined(
        ctx,
        insns,
        idx + 3,
        record_slot,
        record_ty,
        arity,
        bound,
        tmp_slot,
        parent_dispatch_pc,
        parent_default_pc,
        binding_slots,
    )
}

#[allow(clippy::too_many_arguments)]
fn walk_component_typeswitch(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    idx: usize,
    record_slot: u16,
    record_ty: &str,
    arity: usize,
    bound: &[RecordComponent],
    tmp_slot: u16,
    binding_slots: &mut Vec<u16>,
) -> Option<Vec<PatternArm>> {
    let load_tmp: &Instruction = insns.get(idx + 2)?;
    if object_local_slot(load_tmp) != Some(tmp_slot) {
        return None;
    }
    let indy: &Instruction = insns.get(idx + 4)?;
    type_switch_indy_name(ctx.cf, indy, ctx.bootstraps)?;
    let switch_insn: &Instruction = insns.get(idx + 5)?;
    let targets: SwitchTargets = switch_targets(switch_insn)?;
    let nested_dispatch_pc: u32 = insns.get(idx)?.pc;

    let mut out: Vec<PatternArm> = Vec::new();
    for (_key, case_pc) in &targets.cases {
        let case_idx: usize = insn_index_at_pc(insns, *case_pc)?;
        let cast_idx: usize = if insns
            .get(case_idx)
            .is_some_and(|i: &Instruction| i.opcode == 0xC0)
        {
            case_idx
        } else if object_local_slot(insns.get(case_idx)?) == Some(tmp_slot)
            && insns
                .get(case_idx + 1)
                .is_some_and(|i: &Instruction| i.opcode == 0xC0)
        {
            case_idx + 1
        } else {
            continue;
        };
        let cast: &Instruction = insns.get(cast_idx)?;
        let comp_ty: String = descriptor::binary_to_source(&class_ref_at(ctx.cf, cast)?);
        let store_bind: &Instruction = insns.get(cast_idx + 1)?;
        let bind_slot: u16 = object_local_slot(store_bind)?;
        let mut next_bound: Vec<RecordComponent> = bound.to_vec();
        next_bound.push(RecordComponent {
            ty: comp_ty,
            name: local_name(bind_slot, ctx.params),
            slot: bind_slot,
        });
        let arms: Vec<PatternArm> = walk_record_components(
            ctx,
            insns,
            cast_idx + 2,
            record_slot,
            record_ty,
            arity,
            next_bound,
            nested_dispatch_pc,
            *case_pc,
            binding_slots,
        )?;
        out.extend(arms);
    }
    (!out.is_empty()).then_some(out)
}

#[allow(clippy::too_many_arguments)]
fn walk_component_inlined(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    idx: usize,
    record_slot: u16,
    record_ty: &str,
    arity: usize,
    bound: Vec<RecordComponent>,
    tmp_slot: u16,
    parent_dispatch_pc: u32,
    parent_default_pc: u32,
    binding_slots: &mut Vec<u16>,
) -> Option<Vec<PatternArm>> {
    let load_tmp: &Instruction = insns.get(idx)?;
    if object_local_slot(load_tmp) != Some(tmp_slot) {
        return None;
    }
    let instanceof: &Instruction = insns.get(idx + 1)?;
    if instanceof.opcode != 0xC1 {
        return None;
    }
    let comp_ty: String = descriptor::binary_to_source(&class_ref_at(ctx.cf, instanceof)?);
    let ifeq: &Instruction = insns.get(idx + 2)?;
    if ifeq.opcode != 0x99 {
        return None;
    }
    let cast: &Instruction = insns.get(idx + 4)?;
    if cast.opcode != 0xC0 {
        return None;
    }
    let store_bind: &Instruction = insns.get(idx + 5)?;
    let bind_slot: u16 = object_local_slot(store_bind)?;
    let goto: &Instruction = insns.get(idx + 6)?;
    let body_pc: u32 = if goto.opcode == 0xA7 {
        branch_abs(goto)?
    } else {
        goto.pc
    };
    let body_idx: usize = insn_index_at_pc(insns, body_pc)?;
    let _ = (parent_dispatch_pc, parent_default_pc);
    let mut next_bound: Vec<RecordComponent> = bound;
    next_bound.push(RecordComponent {
        ty: comp_ty,
        name: local_name(bind_slot, ctx.params),
        slot: bind_slot,
    });
    walk_record_components(
        ctx,
        insns,
        body_idx,
        record_slot,
        record_ty,
        arity,
        next_bound,
        parent_dispatch_pc,
        parent_default_pc,
        binding_slots,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_pattern_arm(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    arm_pc: u32,
    selector_slot: u16,
    dispatch_pc: u32,
    case_index: i32,
    low: i32,
    null_before_index: &mut Option<i32>,
) -> Option<PatternArm> {
    let start_idx: usize = insn_index_at_pc(insns, arm_pc)?;
    let end_pc: u32 = arm_end_pc(insns, start_idx);
    let slice: &[Instruction] = arm_slice(insns, start_idx, end_pc);
    let first: &Instruction = slice.first()?;
    let switch_value: i32 = low + case_index;
    let has_cast: bool = slice.get(1).is_some_and(|i: &Instruction| i.opcode == 0xC0);
    if switch_value == -1 && !has_cast {
        let body: String = lift_arm_body(ctx, insns, start_idx)?;
        *null_before_index = Some(case_index);
        return Some(PatternArm {
            label: "null".to_string(),
            guard: None,
            body,
            binding_slots: Vec::new(),
        });
    }
    if first.opcode != 0x19 && first.opcode != 0x2A && !(0x2A..=0x2D).contains(&first.opcode) {
        return None;
    }
    if !has_cast {
        return None;
    }
    let cast_insn: &Instruction = slice.get(1)?;
    let binary_ty: String = class_ref_at(ctx.cf, cast_insn)?;
    let ty: String = descriptor::binary_to_source(&binary_ty);
    let store_insn: &Instruction = slice.get(2)?;
    let bind_slot: u16 = object_local_slot(store_insn)?;
    let var: String = local_name(bind_slot, ctx.params);
    let _ = selector_slot;

    if let Some(record) =
        try_record_deconstruction(ctx, insns, start_idx + 3, bind_slot, dispatch_pc, end_pc)
    {
        let pattern: String = render_record_pattern(&ty, &record.components);
        let mut binding_slots: Vec<u16> = record.components.iter().map(|c| c.slot).collect();
        binding_slots.push(bind_slot);
        let body: String = lift_arm_body(ctx, insns, record.body_idx)?;
        return Some(PatternArm {
            label: pattern,
            guard: None,
            body,
            binding_slots,
        });
    }

    let (guard, body_idx): (Option<String>, usize) =
        extract_guard(ctx, insns, start_idx + 3, dispatch_pc, end_pc, &var)?;
    let body: String = lift_arm_body(ctx, insns, body_idx)?;
    Some(PatternArm {
        label: format!("{ty} {var}"),
        guard,
        body,
        binding_slots: vec![bind_slot],
    })
}

fn lift_arm_body(ctx: &RenderCtx<'_>, insns: &[Instruction], body_idx: usize) -> Option<String> {
    let body_end: u32 = arm_end_pc(insns, body_idx);
    let slice: &[Instruction] = arm_slice(insns, body_idx, body_end);
    Some(lift_value_slice(ctx, slice)?.render())
}

fn extract_guard(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    from_idx: usize,
    dispatch_pc: u32,
    end_pc: u32,
    var: &str,
) -> Option<(Option<String>, usize)> {
    let cond_branch_idx: Option<usize> = insns[from_idx..]
        .iter()
        .enumerate()
        .take_while(|(_, ins): &(usize, &Instruction)| ins.pc < end_pc)
        .find_map(|(rel, ins): (usize, &Instruction)| {
            (is_conditional_branch(ins.opcode)
                && redispatch_follows(insns, from_idx + rel + 1, dispatch_pc))
            .then_some(from_idx + rel)
        });
    let Some(branch_idx): Option<usize> = cond_branch_idx else {
        return Some((None, from_idx));
    };
    let cond_slice: &[Instruction] = &insns[from_idx..=branch_idx];
    let guard: String = lift_guard_condition(ctx, cond_slice, var)?;
    let body_pc: u32 = branch_abs(&insns[branch_idx])?;
    let body_idx: usize = insn_index_at_pc(insns, body_pc)?;
    Some((Some(guard), body_idx))
}

fn redispatch_follows(insns: &[Instruction], from_idx: usize, dispatch_pc: u32) -> bool {
    let goto: Option<&Instruction> = insns
        .get(from_idx..from_idx + 3)
        .and_then(|w: &[Instruction]| w.last());
    matches!(
        (insns.get(from_idx), goto),
        (Some(store), Some(g))
            if matches!(store.opcode, 0x10 | 0x11 | 0x03..=0x08)
                && g.opcode == 0xA7
                && branch_abs(g) == Some(dispatch_pc)
    ) || insns
        .get(from_idx)
        .is_some_and(|ins: &Instruction| ins.opcode == 0xA7 && branch_abs(ins) == Some(dispatch_pc))
}

const fn is_conditional_branch(op: u8) -> bool {
    matches!(op, 0x99..=0xA6 | 0xC6 | 0xC7)
}

fn branch_abs(insn: &Instruction) -> Option<u32> {
    match &insn.operands {
        Operands::Branch(off) => Some(abs_target(insn.pc, *off)),
        _ => None,
    }
}

struct RecordDeconstruction {
    components: Vec<RecordComponent>,
    body_idx: usize,
}

fn try_record_deconstruction(
    ctx: &RenderCtx<'_>,
    insns: &[Instruction],
    from_idx: usize,
    record_slot: u16,
    _dispatch_pc: u32,
    end_pc: u32,
) -> Option<RecordDeconstruction> {
    let mut components: Vec<RecordComponent> = Vec::new();
    let mut idx: usize = from_idx;
    loop {
        let aload: &Instruction = insns.get(idx)?;
        if aload.pc >= end_pc {
            break;
        }
        if object_local_slot(aload) != Some(record_slot) {
            break;
        }
        let invoke: &Instruction = insns.get(idx + 1)?;
        if invoke.opcode != 0xB6 && invoke.opcode != 0xB9 {
            break;
        }
        let _accessor: String = invoke_method_name(ctx.cf, invoke)?;
        let cast: &Instruction = insns.get(idx + 2)?;
        if cast.opcode != 0xC0 {
            break;
        }
        let comp_ty: String = descriptor::binary_to_source(&class_ref_at(ctx.cf, cast)?);
        let store_tmp: &Instruction = insns.get(idx + 3)?;
        if object_local_slot(store_tmp).is_none() {
            break;
        }
        let reload: &Instruction = insns.get(idx + 4)?;
        let store_bind: &Instruction = insns.get(idx + 5)?;
        let bind_slot: u16 = object_local_slot(store_bind)?;
        if object_local_slot(reload).is_none() {
            break;
        }
        components.push(RecordComponent {
            ty: comp_ty,
            name: local_name(bind_slot, ctx.params),
            slot: bind_slot,
        });
        idx += 6;
    }
    if components.is_empty() {
        return None;
    }
    Some(RecordDeconstruction {
        components,
        body_idx: idx,
    })
}

fn invoke_method_name(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return None,
    };
    let reference: String = bytecode::resolve_ref(cf, idx)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    let (_owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(name.to_string())
}

fn render_record_pattern(ty: &str, components: &[RecordComponent]) -> String {
    let inner: String = components
        .iter()
        .map(|c: &RecordComponent| format!("{} {}", c.ty, c.name))
        .collect::<Vec<String>>()
        .join(", ");
    format!("{ty}({inner})")
}

fn lift_guard_condition(ctx: &RenderCtx<'_>, slice: &[Instruction], var: &str) -> Option<String> {
    let branch: &Instruction = slice.last()?;
    let mut body: &[Instruction] = &slice[..slice.len() - 1];
    let fused_cmp: Option<u8> = body
        .last()
        .map(|ins: &Instruction| ins.opcode)
        .filter(|op: &u8| matches!(op, 0x94..=0x98));
    if fused_cmp.is_some() {
        body = &body[..body.len() - 1];
    }
    let mut stack: Vec<Expr> = Vec::new();
    for ins in body {
        match lift_one(
            ctx.cf,
            ins,
            &mut stack,
            ctx.params,
            ctx.bootstraps,
            ctx.has_this,
            ctx.bool_return,
        ) {
            LiftResult::Pushed => {}
            _ => return None,
        }
    }
    let cond: String = build_guard_expr(
        branch.opcode,
        &mut stack,
        fused_cmp.is_some(),
        var,
        &ctx.bool_array_names,
    )?;
    Some(cond)
}

fn boolean_array_store(
    stack: &mut Vec<Expr>,
    bool_arrays: &BTreeMap<String, u8>,
) -> Option<String> {
    let len: usize = stack.len();
    if len < 3 {
        return None;
    }
    let array: &Expr = &stack[len - 3];
    if !is_boolean_element_array(array, bool_arrays) {
        return None;
    }
    let value: &Expr = &stack[len - 1];
    let literal: &str = match value {
        Expr::Const(c) if c == "0" => "false",
        Expr::Const(c) if c == "1" => "true",
        _ => return None,
    };
    let index: &Expr = &stack[len - 2];
    let stmt: String = format!("{}[{}] = {literal}", array.render(), index.render());
    stack.truncate(len - 3);
    Some(stmt)
}

fn boolean_local_store(
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    params: &[(u16, String)],
    slot_types: &BTreeMap<u16, String>,
) -> Option<String> {
    let slot: u16 = int_store_slot(insn)?;
    if slot_types.get(&slot).map(String::as_str) != Some("boolean") {
        return None;
    }
    let rendered: String = stack.last()?.render();
    let value: String = int_literal_as_bool(&rendered)
        .map(str::to_owned)
        .or_else(|| bool_ternary_condition(&rendered))?;
    stack.pop();
    Some(format!("{} = {value}", local_name(slot, params)))
}

fn bool_ternary_condition(rendered: &str) -> Option<String> {
    let inner: &str = rendered.strip_prefix('(')?.strip_suffix(')')?;
    let (cond, arms): (&str, &str) = inner.rsplit_once(" ? ")?;
    match arms {
        "1 : 0" => Some(cond.to_owned()),
        "0 : 1" => Some(invert(cond)),
        _ => None,
    }
}

fn boolean_array_load_render(
    expr: &Expr,
    negate: bool,
    bool_arrays: &BTreeMap<String, u8>,
) -> Option<String> {
    let Expr::ArrayLoad { array, .. } = expr else {
        return None;
    };
    if !is_boolean_element_array(array, bool_arrays) {
        return None;
    }
    let rendered: String = expr.render();
    Some(if negate {
        format!("!{rendered}")
    } else {
        rendered
    })
}

fn build_guard_expr(
    branch_op: u8,
    stack: &mut Vec<Expr>,
    fused_cmp: bool,
    _var: &str,
    bool_arrays: &BTreeMap<String, u8>,
) -> Option<String> {
    if fused_cmp {
        let rhs: Expr = stack.pop()?;
        let lhs: Expr = stack.pop()?;
        let op: &str = guard_compare_op(branch_op)?;
        return Some(format!("{} {op} {}", lhs.render(), rhs.render()));
    }
    let satisfied: String = match branch_op {
        0x99 | 0x9A => {
            let lhs: Expr = stack.pop()?;
            if let Some(rendered) = boolean_array_load_render(&lhs, branch_op == 0x9A, bool_arrays)
            {
                return Some(rendered);
            }
            let op: &str = if branch_op == 0x99 { "!= 0" } else { "== 0" };
            format!("{} {op}", lhs.render())
        }
        0x9B..=0xA4 => {
            let rhs: Expr = stack.pop()?;
            let lhs: Expr = stack.pop()?;
            let op: &str = guard_compare_op(branch_op)?;
            format!("{} {op} {}", lhs.render(), rhs.render())
        }
        0xA5 | 0xA6 => {
            let rhs: Expr = stack.pop()?;
            let lhs: Expr = stack.pop()?;
            let op: &str = if branch_op == 0xA5 { "==" } else { "!=" };
            format!("{} {op} {}", lhs.render(), rhs.render())
        }
        0xC6 => format!("{} == null", stack.pop()?.render()),
        0xC7 => format!("{} != null", stack.pop()?.render()),
        _ => return None,
    };
    Some(satisfied)
}

const fn guard_compare_op(branch_op: u8) -> Option<&'static str> {
    Some(match branch_op {
        0x99 | 0x9F | 0xA5 => "==",
        0x9A | 0xA0 | 0xA6 => "!=",
        0x9B | 0xA1 => "<",
        0x9C | 0xA2 => ">=",
        0x9D | 0xA3 => ">",
        0x9E | 0xA4 => "<=",
        _ => return None,
    })
}

fn render_pattern_switch(subject: &Expr, arms: &[PatternArm], default_arm: Option<&str>) -> String {
    let mut src: String = format!("switch ({}) {{\n", subject.render());
    for arm in arms {
        match &arm.guard {
            Some(guard) => {
                let _ = writeln!(
                    src,
                    "            case {} when {} -> ({});",
                    arm.label, guard, arm.body
                );
            }
            None => {
                let _ = writeln!(src, "            case {} -> ({});", arm.label, arm.body);
            }
        }
    }
    if let Some(def) = default_arm {
        let _ = writeln!(src, "            default -> ({def});");
    }
    let _ = write!(src, "        }}");
    src
}

fn fold_make_concat_arm(
    ctx: &RenderCtx<'_>,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
) -> Option<()> {
    let Operands::InvokeDynamic(idx) = &insn.operands else {
        return None;
    };
    let crate::classfile::ConstantPoolEntry::InvokeDynamic {
        bootstrap_method_attr_index,
        name_and_type_index,
    } = ctx.cf.constant_pool.get(usize::from(*idx))?
    else {
        return None;
    };
    let (_name, desc): (String, String) = name_and_type_parts(ctx.cf, *name_and_type_index)?;
    let parsed: MethodDescriptor = descriptor::parse_method(&desc)?;
    let bsm: &crate::attributes::BootstrapMethod = ctx
        .bootstraps
        .get(usize::from(*bootstrap_method_attr_index))?;
    let bsm_name: String = method_handle_ref_name(ctx.cf, bsm.method_ref_index)?;
    if !matches!(bsm_name.as_str(), "makeConcatWithConstants" | "makeConcat") {
        return None;
    }
    let argc: usize = parsed.params.len();
    if argc > stack.len() {
        return None;
    }
    let args: Vec<Expr> = stack.split_off(stack.len() - argc);
    let recipe: Option<String> = (bsm_name == "makeConcatWithConstants")
        .then(|| bsm.arguments.first().copied())
        .flatten()
        .and_then(|a: u16| bootstrap_string_arg(ctx.cf, a));
    stack.push(fold_string_concat(recipe.as_deref(), &args));
    Some(())
}

fn strip_outer_not(cond: &str) -> Option<&str> {
    let inner: &str = cond.strip_prefix("!(")?.strip_suffix(')')?;
    let mut depth: i32 = 0;
    for ch in inner.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then_some(inner)
}

fn invert(cond: &str) -> String {
    if let Some(inner) = strip_outer_not(cond) {
        return inner.to_string();
    }
    if let Some(rest) = cond.strip_suffix(" == 0") {
        return format!("{rest} != 0");
    }
    if let Some(rest) = cond.strip_suffix(" != 0") {
        return format!("{rest} == 0");
    }
    if let Some(rest) = cond.strip_suffix(" == null") {
        return format!("{rest} != null");
    }
    if let Some(rest) = cond.strip_suffix(" != null") {
        return format!("{rest} == null");
    }
    if cond.contains(" < ") {
        return cond.replacen(" < ", " >= ", 1);
    }
    if cond.contains(" <= ") {
        return cond.replacen(" <= ", " > ", 1);
    }
    if cond.contains(" > ") {
        return cond.replacen(" > ", " <= ", 1);
    }
    if cond.contains(" >= ") {
        return cond.replacen(" >= ", " < ", 1);
    }
    if cond.contains(" == ") {
        return cond.replacen(" == ", " != ", 1);
    }
    if cond.contains(" != ") {
        return cond.replacen(" != ", " == ", 1);
    }
    format!("!({cond})")
}

fn header_cond_true_target(cfg: &Cfg, head: BlockId) -> Option<BlockId> {
    let block: &BasicBlock = &cfg.blocks[head.0 as usize];
    block
        .successors
        .iter()
        .find(|e| matches!(e.kind, EdgeKind::CondTrue))
        .map(|e| e.target)
}

fn format_switch_key(key: &SwitchKey, fallback_idx: usize) -> String {
    match key {
        SwitchKey::Range { low, high } => (*low..=*high)
            .map(|v: i32| v.to_string())
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(vs) if !vs.is_empty() => vs
            .iter()
            .map(i32::to_string)
            .collect::<Vec<String>>()
            .join(", "),
        SwitchKey::Values(_) => fallback_idx.to_string(),
    }
}

fn branch_targets(insns: &[Instruction]) -> BTreeSet<u32> {
    let mut targets: BTreeSet<u32> = BTreeSet::new();
    for insn in insns {
        if let Some(t) = branch_target(insn) {
            targets.insert(t);
        }
        match &insn.operands {
            Operands::TableSwitch {
                default, offsets, ..
            } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for off in offsets {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            Operands::LookupSwitch { default, pairs } => {
                targets.insert((i64::from(insn.pc) + i64::from(*default)) as u32);
                for (_, off) in pairs {
                    targets.insert((i64::from(insn.pc) + i64::from(*off)) as u32);
                }
            }
            _ => {}
        }
    }
    targets
}

enum LiftResult {
    Pushed,
    Elided,
    Statement(String),
    ControlFlow(String),
    Unhandled,
}

fn local_name(index: u16, params: &[(u16, String)]) -> String {
    params
        .iter()
        .find(|(i, _)| *i == index)
        .map_or_else(|| format!("var{index}"), |(_, n)| n.clone())
}

pub(crate) const MAX_DUP_EXPR_NODES: usize = 1024;

pub(crate) fn expr_node_count_capped(e: &Expr, cap: usize) -> usize {
    fn walk(e: &Expr, cap: usize, acc: &mut usize) {
        if *acc >= cap {
            return;
        }
        *acc += 1;
        match e {
            Expr::Binary { lhs, rhs, .. }
            | Expr::Cmp { lhs, rhs }
            | Expr::ArrayLoad {
                array: lhs,
                index: rhs,
            } => {
                walk(lhs, cap, acc);
                walk(rhs, cap, acc);
            }
            Expr::Unary { value, .. }
            | Expr::Cast { value, .. }
            | Expr::InstanceOf { value, .. }
            | Expr::ArrayLength(value)
            | Expr::NewArray { size: value, .. } => walk(value, cap, acc),
            Expr::Invoke { receiver, args, .. } => {
                if let Some(r) = receiver {
                    walk(r, cap, acc);
                }
                for a in args {
                    walk(a, cap, acc);
                }
            }
            Expr::ArrayInit { elements, .. } => {
                for el in elements {
                    walk(el, cap, acc);
                }
            }
            Expr::Field { receiver, .. } => walk(receiver, cap, acc),
            Expr::Const(_)
            | Expr::Local(_)
            | Expr::This
            | Expr::StaticField { .. }
            | Expr::New(_)
            | Expr::Opaque(_) => {}
        }
    }
    let mut acc: usize = 0;
    walk(e, cap, &mut acc);
    acc
}

#[cfg(feature = "opcode-census")]
thread_local! {
    pub(crate) static UNHANDLED_OPS: std::cell::RefCell<std::collections::BTreeMap<u8, u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

thread_local! {




    static OBJECT_LOCALS: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

thread_local! {




    static BOOLEAN_LOCALS: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
}

thread_local! {
    static OBJECT_LOCAL_ARRAY_CASTS: RefCell<BTreeMap<String, String>> =
        const { RefCell::new(BTreeMap::new()) };
}

thread_local! {
    static ANON_INNERS: RefCell<BTreeMap<String, ClassFile>> =
        const { RefCell::new(BTreeMap::new()) };
}

thread_local! {
    static ANON_INLINE_STACK: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
struct ApiOutlineKey {
    owner: String,
    name: String,
    descriptor: String,
    fingerprint: [u8; 32],
}

#[derive(Clone)]
struct ApiOutlineProjection {
    owner: String,
    name: String,
}

thread_local! {
    static API_OUTLINE_PROJECTIONS: RefCell<BTreeMap<ApiOutlineKey, ApiOutlineProjection>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn with_api_outline_projections<T>(
    projections: BTreeMap<ApiOutlineKey, ApiOutlineProjection>,
    body: impl FnOnce() -> T,
) -> T {
    let previous: BTreeMap<ApiOutlineKey, ApiOutlineProjection> = API_OUTLINE_PROJECTIONS.with(
        |slot: &RefCell<BTreeMap<ApiOutlineKey, ApiOutlineProjection>>| slot.replace(projections),
    );
    let result: T = body();
    API_OUTLINE_PROJECTIONS.with(
        |slot: &RefCell<BTreeMap<ApiOutlineKey, ApiOutlineProjection>>| slot.replace(previous),
    );
    result
}

fn api_outline_projection(
    owner: &str,
    name: &str,
    descriptor: &str,
) -> Option<ApiOutlineProjection> {
    API_OUTLINE_PROJECTIONS.with(
        |slot: &RefCell<BTreeMap<ApiOutlineKey, ApiOutlineProjection>>| {
            let borrowed: std::cell::Ref<'_, BTreeMap<ApiOutlineKey, ApiOutlineProjection>> =
                slot.borrow();
            let mut matching = borrowed.iter().filter_map(
                |(key, projection): (&ApiOutlineKey, &ApiOutlineProjection)| {
                    (key.owner == owner && key.name == name && key.descriptor == descriptor)
                        .then_some(projection)
                },
            );
            let projection: ApiOutlineProjection = matching.next()?.clone();
            matching.next().is_none().then_some(projection)
        },
    )
}

const API_OUTLINE_MAX_CLASSES: usize = 512;
const API_OUTLINE_MAX_METHODS: usize = 512;
const API_OUTLINE_MAX_INSTRUCTIONS: usize = 512;
const API_OUTLINE_MAX_DEPTH: usize = 16;
const API_OUTLINE_MAX_PROJECTIONS: usize = 32;

struct KnownApiOutline {
    descriptor: &'static str,
    fingerprint: [u8; 32],
    owner: &'static str,
    name: &'static str,
}

const KNOWN_API_OUTLINES: [KnownApiOutline; 6] = [
    KnownApiOutline {
        descriptor: "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/Map;",
        fingerprint: [
            41, 47, 23, 222, 141, 57, 83, 159, 84, 126, 25, 32, 136, 173, 85, 241, 216, 69, 209,
            160, 189, 113, 3, 153, 187, 214, 143, 1, 216, 211, 86, 242,
        ],
        owner: "java/util/Map",
        name: "of",
    },
    KnownApiOutline {
        descriptor: "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/List;",
        fingerprint: [
            221, 73, 203, 135, 154, 68, 153, 25, 19, 4, 110, 191, 177, 6, 214, 252, 243, 254, 27,
            140, 168, 34, 73, 204, 192, 141, 219, 178, 220, 195, 93, 132,
        ],
        owner: "java/util/List",
        name: "of",
    },
    KnownApiOutline {
        descriptor: "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/util/Set;",
        fingerprint: [
            121, 183, 103, 63, 203, 134, 135, 200, 63, 146, 135, 217, 3, 126, 162, 160, 126, 101,
            249, 190, 51, 116, 12, 13, 159, 146, 65, 136, 93, 33, 91, 52,
        ],
        owner: "java/util/Set",
        name: "of",
    },
    KnownApiOutline {
        descriptor: "(Ljava/util/function/ToIntFunction;)Ljava/util/Comparator;",
        fingerprint: [
            206, 62, 114, 158, 85, 96, 89, 109, 168, 84, 187, 69, 197, 139, 204, 41, 23, 33, 177,
            175, 153, 39, 235, 92, 192, 132, 100, 102, 92, 83, 135, 71,
        ],
        owner: "java/util/Comparator",
        name: "comparingInt",
    },
    KnownApiOutline {
        descriptor: "(Ljava/lang/Object;)Z",
        fingerprint: [
            37, 120, 140, 251, 243, 135, 222, 20, 7, 253, 201, 179, 44, 149, 20, 37, 156, 204, 51,
            219, 237, 214, 142, 150, 176, 83, 237, 255, 156, 215, 20, 146,
        ],
        owner: "java/util/Objects",
        name: "nonNull",
    },
    KnownApiOutline {
        descriptor: "(II)Ljava/util/stream/IntStream;",
        fingerprint: [
            142, 226, 192, 159, 74, 124, 80, 41, 20, 26, 152, 98, 25, 128, 172, 54, 228, 100, 63,
            178, 120, 210, 46, 114, 187, 113, 52, 87, 108, 8, 13, 126,
        ],
        owner: "java/util/stream/IntStream",
        name: "range",
    },
];

fn api_outline_plan<'a>(
    classes: impl Iterator<Item = &'a ClassFile>,
) -> BTreeMap<ApiOutlineKey, ApiOutlineProjection> {
    let classes: Vec<&ClassFile> = classes.take(API_OUTLINE_MAX_CLASSES + 1).collect();
    if classes.len() > API_OUTLINE_MAX_CLASSES {
        return BTreeMap::new();
    }
    let mut projections: BTreeMap<ApiOutlineKey, ApiOutlineProjection> = BTreeMap::new();
    for class in classes {
        if class.access_flags & (ACC_SYNTHETIC | ACC_FINAL) != (ACC_SYNTHETIC | ACC_FINAL)
            || !class.fields.is_empty()
            || class.methods.len() > API_OUTLINE_MAX_METHODS
            || class.methods.iter().any(|method: &MethodInfo| {
                method.access_flags & ACC_STATIC == 0
                    || class.utf8_at(method.name_index).is_err()
                    || class.utf8_at(method.descriptor_index).is_err()
            })
        {
            continue;
        }
        let Ok(owner) = class.this_class_name() else {
            continue;
        };
        for method in &class.methods {
            let Ok(name) = class.utf8_at(method.name_index) else {
                continue;
            };
            let Ok(descriptor) = class.utf8_at(method.descriptor_index) else {
                continue;
            };
            let Some(known) = KNOWN_API_OUTLINES
                .iter()
                .find(|known: &&KnownApiOutline| known.descriptor == descriptor)
            else {
                continue;
            };
            let mut active: BTreeSet<(String, String)> = BTreeSet::new();
            let Some(fingerprint) =
                api_outline_method_fingerprint(class, name, descriptor, &mut active, 0)
            else {
                continue;
            };
            if fingerprint != known.fingerprint {
                continue;
            }
            let key: ApiOutlineKey = ApiOutlineKey {
                owner: owner.to_owned(),
                name: name.to_owned(),
                descriptor: descriptor.to_owned(),
                fingerprint,
            };
            let projection: ApiOutlineProjection = ApiOutlineProjection {
                owner: known.owner.to_owned(),
                name: known.name.to_owned(),
            };
            projections.insert(key, projection);
            if projections.len() > API_OUTLINE_MAX_PROJECTIONS {
                return BTreeMap::new();
            }
        }
    }
    projections
}

fn api_outline_method_fingerprint(
    class: &ClassFile,
    name: &str,
    descriptor: &str,
    active: &mut BTreeSet<(String, String)>,
    depth: usize,
) -> Option<[u8; 32]> {
    if depth >= API_OUTLINE_MAX_DEPTH || !active.insert((name.to_owned(), descriptor.to_owned())) {
        return None;
    }
    let matching: Vec<&MethodInfo> = class
        .methods
        .iter()
        .filter(|method: &&MethodInfo| {
            class.utf8_at(method.name_index).ok() == Some(name)
                && class.utf8_at(method.descriptor_index).ok() == Some(descriptor)
        })
        .collect();
    let [method]: [&MethodInfo; 1] = matching.try_into().ok()?;
    if method.access_flags & ACC_STATIC == 0 {
        active.remove(&(name.to_owned(), descriptor.to_owned()));
        return None;
    }
    let MethodCode::Decoded(code): MethodCode = find_code(class, method) else {
        active.remove(&(name.to_owned(), descriptor.to_owned()));
        return None;
    };
    if !code.exception_table.is_empty() || code.dropped_exception_entries != 0 {
        active.remove(&(name.to_owned(), descriptor.to_owned()));
        return None;
    }
    let instructions: Vec<Instruction> = validate_code_attribute(class, &code).ok()?;
    if instructions.len() > API_OUTLINE_MAX_INSTRUCTIONS {
        active.remove(&(name.to_owned(), descriptor.to_owned()));
        return None;
    }
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(descriptor.as_bytes());
    hasher.update([0]);
    for instruction in &instructions {
        hasher.update([instruction.opcode, u8::from(instruction.wide)]);
        api_outline_operand_fingerprint(
            class,
            &instructions,
            instruction,
            active,
            depth,
            &mut hasher,
        )?;
        hasher.update([0xff]);
    }
    active.remove(&(name.to_owned(), descriptor.to_owned()));
    Some(hasher.finalize().into())
}

fn api_outline_operand_fingerprint(
    class: &ClassFile,
    instructions: &[Instruction],
    instruction: &Instruction,
    active: &mut BTreeSet<(String, String)>,
    depth: usize,
    hasher: &mut Sha256,
) -> Option<()> {
    match &instruction.operands {
        Operands::None => {}
        Operands::Byte(value) | Operands::Short(value) => hasher.update(value.to_be_bytes()),
        Operands::Local(index) => hasher.update(index.to_be_bytes()),
        Operands::Branch(_) => {
            let target: u32 = branch_target(instruction)?;
            let index: usize = instructions
                .iter()
                .position(|item: &Instruction| item.pc == target)?;
            hasher.update(u32::try_from(index).ok()?.to_be_bytes());
        }
        Operands::ConstPool(index) => {
            api_outline_pool_fingerprint(class, *index, active, depth, hasher)?;
        }
        Operands::Iinc { index, delta } => {
            hasher.update(index.to_be_bytes());
            hasher.update(delta.to_be_bytes());
        }
        Operands::NewArray(kind) => hasher.update([*kind]),
        Operands::InvokeInterface { index, count } => {
            hasher.update([*count]);
            api_outline_pool_fingerprint(class, *index, active, depth, hasher)?;
        }
        Operands::InvokeDynamic(_) => return None,
        Operands::MultiANewArray { index, dimensions } => {
            hasher.update([*dimensions]);
            api_outline_pool_fingerprint(class, *index, active, depth, hasher)?;
        }
        Operands::TableSwitch {
            default,
            low,
            high,
            offsets,
        } => {
            hasher.update(low.to_be_bytes());
            hasher.update(high.to_be_bytes());
            api_outline_switch_target(instructions, instruction.pc, *default, hasher)?;
            for offset in offsets {
                api_outline_switch_target(instructions, instruction.pc, *offset, hasher)?;
            }
        }
        Operands::LookupSwitch { default, pairs } => {
            api_outline_switch_target(instructions, instruction.pc, *default, hasher)?;
            for (key, offset) in pairs {
                hasher.update(key.to_be_bytes());
                api_outline_switch_target(instructions, instruction.pc, *offset, hasher)?;
            }
        }
    }
    Some(())
}

fn api_outline_switch_target(
    instructions: &[Instruction],
    pc: u32,
    offset: i32,
    hasher: &mut Sha256,
) -> Option<()> {
    let target: u32 = pc.checked_add_signed(offset)?;
    let index: usize = instructions
        .iter()
        .position(|item: &Instruction| item.pc == target)?;
    hasher.update(u32::try_from(index).ok()?.to_be_bytes());
    Some(())
}

fn api_outline_pool_fingerprint(
    class: &ClassFile,
    index: u16,
    active: &mut BTreeSet<(String, String)>,
    depth: usize,
    hasher: &mut Sha256,
) -> Option<()> {
    let reference: String = bytecode::resolve_ref(class, index)?;
    if let Some((owner, name, descriptor)) = split_member(&reference)
        && class.this_class_name().ok() == Some(owner.as_str())
    {
        let nested: [u8; 32] =
            api_outline_method_fingerprint(class, &name, &descriptor, active, depth + 1)?;
        hasher.update(nested);
    } else {
        hasher.update(reference.as_bytes());
    }
    Some(())
}

thread_local! {
    static RECORD_ARITIES: RefCell<BTreeMap<String, usize>> =
        const { RefCell::new(BTreeMap::new()) };
}

thread_local! {
    static DEFERRED_ALLOCATIONS: RefCell<DeferredAllocationPlan> =
        RefCell::new(DeferredAllocationPlan::default());
}

fn with_deferred_allocations<T>(plan: DeferredAllocationPlan, body: impl FnOnce() -> T) -> T {
    let previous: DeferredAllocationPlan =
        DEFERRED_ALLOCATIONS.with(|slot: &RefCell<DeferredAllocationPlan>| slot.replace(plan));
    let result: T = body();
    DEFERRED_ALLOCATIONS.with(|slot: &RefCell<DeferredAllocationPlan>| slot.replace(previous));
    result
}

fn allocation_store_is_deferred(pc: u32) -> bool {
    DEFERRED_ALLOCATIONS
        .with(|slot: &RefCell<DeferredAllocationPlan>| slot.borrow().elides_store_at(pc))
}

fn deferred_allocation_class(pc: u32) -> Option<String> {
    DEFERRED_ALLOCATIONS.with(|slot: &RefCell<DeferredAllocationPlan>| {
        slot.borrow().merged_construction_at(pc).map(str::to_owned)
    })
}

thread_local! {
    static ENUM_CONSTANTS: RefCell<BTreeMap<String, Vec<String>>> =
        const { RefCell::new(BTreeMap::new()) };
}

thread_local! {
    static SWITCHMAP_INVERSE: RefCell<BTreeMap<String, BTreeMap<i32, String>>> =
        const { RefCell::new(BTreeMap::new()) };
}

fn with_enum_metadata<T>(
    constants: BTreeMap<String, Vec<String>>,
    switchmaps: BTreeMap<String, BTreeMap<i32, String>>,
    body: impl FnOnce() -> T,
) -> T {
    let prev_constants: BTreeMap<String, Vec<String>> = ENUM_CONSTANTS
        .with(|slot: &RefCell<BTreeMap<String, Vec<String>>>| slot.replace(constants));
    let prev_switchmaps: BTreeMap<String, BTreeMap<i32, String>> = SWITCHMAP_INVERSE
        .with(|slot: &RefCell<BTreeMap<String, BTreeMap<i32, String>>>| slot.replace(switchmaps));
    let result: T = body();
    ENUM_CONSTANTS
        .with(|slot: &RefCell<BTreeMap<String, Vec<String>>>| slot.replace(prev_constants));
    SWITCHMAP_INVERSE.with(|slot: &RefCell<BTreeMap<String, BTreeMap<i32, String>>>| {
        slot.replace(prev_switchmaps)
    });
    result
}

fn enum_constant_name(enum_internal: &str, ordinal: i32) -> Option<String> {
    ENUM_CONSTANTS.with(|slot: &RefCell<BTreeMap<String, Vec<String>>>| {
        let borrowed: std::cell::Ref<'_, BTreeMap<String, Vec<String>>> = slot.borrow();
        let names: &Vec<String> = borrowed.get(enum_internal)?;
        let index: usize = usize::try_from(ordinal).ok()?;
        names.get(index).cloned()
    })
}

fn switchmap_label(field_ref: &str, key: i32) -> Option<String> {
    SWITCHMAP_INVERSE.with(|slot: &RefCell<BTreeMap<String, BTreeMap<i32, String>>>| {
        slot.borrow().get(field_ref)?.get(&key).cloned()
    })
}

fn enum_constant_order(cf: &ClassFile) -> Vec<String> {
    cf.fields
        .iter()
        .filter(|f: &&FieldInfo| f.access_flags & ACC_ENUM != 0)
        .filter_map(|f: &FieldInfo| cf.utf8_at(f.name_index).ok().map(str::to_string))
        .collect()
}

fn switchmap_inversions(cf: &ClassFile) -> BTreeMap<String, BTreeMap<i32, String>> {
    let mut out: BTreeMap<String, BTreeMap<i32, String>> = BTreeMap::new();
    let Some(clinit): Option<&MethodInfo> = cf.methods.iter().find(|m: &&MethodInfo| {
        cf.utf8_at(m.name_index)
            .is_ok_and(|n: &str| n == "<clinit>")
    }) else {
        return out;
    };
    let MethodCode::Decoded(code): MethodCode = find_code(cf, clinit) else {
        return out;
    };
    let Ok(insns): Result<Vec<Instruction>> = disassemble(&code.code) else {
        return out;
    };
    let mut i: usize = 0;
    while i + 4 < insns.len() {
        let array_ref: Option<String> = switchmap_field_ref(cf, &insns[i]);
        let const_name: Option<String> = enum_const_getstatic_name(cf, &insns[i + 1]);
        let is_ordinal: bool = is_ordinal_invoke(cf, &insns[i + 2]);
        let key: Option<i32> = const_int_operand(&insns[i + 3]);
        let is_store: bool = insns[i + 4].opcode == 0x4F;
        if let (Some(array), Some(name), true, Some(k), true) =
            (array_ref, const_name, is_ordinal, key, is_store)
        {
            out.entry(array).or_default().insert(k, name);
            i += 5;
            continue;
        }
        i += 1;
    }
    out
}

fn switchmap_field_ref(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    if insn.opcode != 0xB2 {
        return None;
    }
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *idx)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    owner_name
        .contains("$SwitchMap$")
        .then(|| owner_name.to_string())
}

fn enum_const_getstatic_name(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    if insn.opcode != 0xB2 {
        return None;
    }
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *idx)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    let (_owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(name.to_string())
}

fn is_ordinal_invoke(cf: &ClassFile, insn: &Instruction) -> bool {
    if insn.opcode != 0xB6 {
        return false;
    }
    let Operands::ConstPool(idx) = &insn.operands else {
        return false;
    };
    bytecode::resolve_ref(cf, *idx).is_some_and(|r: String| {
        r.rsplit_once(':')
            .is_some_and(|(member, desc): (&str, &str)| {
                member.ends_with(".ordinal") && desc == "()I"
            })
    })
}

fn ordinal_owner_internal(cf: &ClassFile, insn: &Instruction) -> Option<String> {
    let Operands::ConstPool(idx) = &insn.operands else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *idx)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    let (owner, _name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(owner.to_string())
}

const fn const_int_operand(insn: &Instruction) -> Option<i32> {
    match (insn.opcode, &insn.operands) {
        (0x02, _) => Some(-1),
        (0x03..=0x08, _) => Some(insn.opcode as i32 - 3),
        (0x10 | 0x11, Operands::Byte(v) | Operands::Short(v)) => Some(*v),
        _ => None,
    }
}

fn with_anon_inners<T>(inners: BTreeMap<String, ClassFile>, body: impl FnOnce() -> T) -> T {
    let previous: BTreeMap<String, ClassFile> =
        ANON_INNERS.with(|slot: &RefCell<BTreeMap<String, ClassFile>>| slot.replace(inners));
    let result: T = body();
    ANON_INNERS.with(|slot: &RefCell<BTreeMap<String, ClassFile>>| slot.replace(previous));
    result
}

fn with_record_arities<T>(arities: BTreeMap<String, usize>, body: impl FnOnce() -> T) -> T {
    let previous: BTreeMap<String, usize> =
        RECORD_ARITIES.with(|slot: &RefCell<BTreeMap<String, usize>>| slot.replace(arities));
    let result: T = body();
    RECORD_ARITIES.with(|slot: &RefCell<BTreeMap<String, usize>>| slot.replace(previous));
    result
}

fn record_arity_for(binary_name: &str) -> Option<usize> {
    RECORD_ARITIES
        .with(|slot: &RefCell<BTreeMap<String, usize>>| slot.borrow().get(binary_name).copied())
}

fn anon_inner_for(internal_name: &str) -> Option<ClassFile> {
    ANON_INNERS.with(|slot: &RefCell<BTreeMap<String, ClassFile>>| {
        slot.borrow().get(internal_name).cloned()
    })
}

const ANON_INLINE_MAX_DEPTH: usize = 16;

fn inline_anonymous_class(type_name: &str, ctor_args: &[String]) -> Option<String> {
    let admitted: bool = ANON_INLINE_STACK.with(|slot: &RefCell<Vec<String>>| {
        let mut stack: std::cell::RefMut<'_, Vec<String>> = slot.borrow_mut();
        if stack.len() >= ANON_INLINE_MAX_DEPTH
            || stack.iter().any(|open: &String| open == type_name)
        {
            return false;
        }
        stack.push(type_name.to_owned());
        true
    });
    if !admitted {
        return None;
    }
    let rendered: Option<String> = anon_inner_for(type_name)
        .and_then(|anon: ClassFile| render_anonymous_class(&anon, ctor_args));
    ANON_INLINE_STACK.with(|slot: &RefCell<Vec<String>>| {
        let mut stack: std::cell::RefMut<'_, Vec<String>> = slot.borrow_mut();
        debug_assert_eq!(stack.last().map(String::as_str), Some(type_name));
        stack.pop();
    });
    rendered
}

fn allocation_expression(type_name: &str, ctor_args: &[String]) -> String {
    inline_anonymous_class(type_name, ctor_args)
        .unwrap_or_else(|| format!("new {type_name}({})", ctor_args.join(", ")))
}

fn with_object_locals<T>(
    names: BTreeSet<String>,
    boolean_names: BTreeSet<String>,
    array_casts: BTreeMap<String, String>,
    body: impl FnOnce() -> T,
) -> T {
    let previous: BTreeSet<String> =
        OBJECT_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.replace(names));
    let previous_bool: BTreeSet<String> =
        BOOLEAN_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.replace(boolean_names));
    let previous_casts: BTreeMap<String, String> = OBJECT_LOCAL_ARRAY_CASTS
        .with(|slot: &RefCell<BTreeMap<String, String>>| slot.replace(array_casts));
    let result: T = body();
    OBJECT_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.replace(previous));
    BOOLEAN_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.replace(previous_bool));
    OBJECT_LOCAL_ARRAY_CASTS
        .with(|slot: &RefCell<BTreeMap<String, String>>| slot.replace(previous_casts));
    result
}

fn local_is_object_typed(name: &str) -> bool {
    OBJECT_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.borrow().contains(name))
}

fn local_is_boolean_typed(name: &str) -> bool {
    BOOLEAN_LOCALS.with(|slot: &RefCell<BTreeSet<String>>| slot.borrow().contains(name))
}

fn object_local_array_cast(name: &str) -> Option<String> {
    OBJECT_LOCAL_ARRAY_CASTS
        .with(|slot: &RefCell<BTreeMap<String, String>>| slot.borrow().get(name).cloned())
}

fn object_typed_local_names(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    exc_conflicted: &BTreeSet<u16>,
) -> BTreeSet<String> {
    let concrete: BTreeMap<u16, String> =
        infer_reference_local_types(cf, insns, &BTreeMap::new(), &BTreeSet::new());
    let param_slots: BTreeSet<u16> = params.iter().map(|(i, _): &(u16, String)| *i).collect();
    let mut names: BTreeSet<String> = BTreeSet::new();
    for insn in insns {
        let slot: Option<u16> = match (insn.opcode, &insn.operands) {
            (0x3A, Operands::Local(idx)) => Some(*idx),
            (0x4B..=0x4E, _) => Some(u16::from(insn.opcode - 0x4B)),
            _ => None,
        };
        let Some(slot): Option<u16> = slot else {
            continue;
        };
        if param_slots.contains(&slot) {
            continue;
        }
        if concrete.contains_key(&slot) && !exc_conflicted.contains(&slot) {
            continue;
        }
        names.insert(local_name(slot, params));
    }
    names
}

fn object_local_array_casts(
    cf: &ClassFile,
    insns: &[Instruction],
    params: &[(u16, String)],
    object_locals: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut casts: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicted: BTreeSet<String> = BTreeSet::new();
    for pair in insns.windows(2) {
        let [cast_insn, store_insn] = pair else {
            continue;
        };
        if cast_insn.opcode != 0xC0 {
            continue;
        }
        let slot: u16 = match (store_insn.opcode, &store_insn.operands) {
            (0x3A, Operands::Local(idx)) => *idx,
            (0x4B..=0x4E, _) => u16::from(store_insn.opcode - 0x4B),
            _ => continue,
        };
        let name: String = local_name(slot, params);
        if !object_locals.contains(&name) {
            continue;
        }
        let Some(ty): Option<String> = checkcast_static_type(cf, cast_insn) else {
            continue;
        };
        if !ty.ends_with("[]") {
            continue;
        }
        match casts.get(&name) {
            Some(existing) if existing != &ty => {
                conflicted.insert(name);
            }
            _ => {
                casts.insert(name, ty);
            }
        }
    }
    for name in conflicted {
        casts.remove(&name);
    }
    casts
}

#[cfg(feature = "opcode-census")]
#[inline]
fn census_unhandled(op: u8) {
    UNHANDLED_OPS.with(|m| *m.borrow_mut().entry(op).or_default() += 1);
}

#[cfg(feature = "opcode-census")]
#[must_use]
pub fn drain_unhandled_census() -> std::collections::BTreeMap<u8, u64> {
    UNHANDLED_OPS.with(|m| std::mem::take(&mut *m.borrow_mut()))
}

#[allow(clippy::too_many_lines)]
fn lift_one(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> LiftResult {
    let result: LiftResult =
        lift_one_inner(cf, insn, stack, params, bootstraps, has_this, bool_return);
    #[cfg(feature = "opcode-census")]
    if matches!(result, LiftResult::Unhandled) {
        census_unhandled(insn.opcode);
    }
    result
}

#[allow(clippy::too_many_lines)]
fn lift_one_inner(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    params: &[(u16, String)],
    bootstraps: &[crate::attributes::BootstrapMethod],
    has_this: bool,
    bool_return: bool,
) -> LiftResult {
    let op: u8 = insn.opcode;
    match op {
        0x00 => LiftResult::Pushed,
        0x01 => push(stack, Expr::Const("null".to_string())),
        0x02 => push(stack, Expr::Const("-1".to_string())),
        0x03..=0x08 => push(stack, Expr::Const((i32::from(op) - 3).to_string())),
        0x09 | 0x0A => push(stack, Expr::Const(format!("{}L", op - 9))),
        0x0B..=0x0D => push(stack, Expr::Const(format!("{}.0f", op - 0x0B))),
        0x0E | 0x0F => push(stack, Expr::Const(format!("{}.0", op - 0x0E))),
        0x10 | 0x11 => match &insn.operands {
            Operands::Byte(v) | Operands::Short(v) => push(stack, Expr::Const(v.to_string())),
            _ => LiftResult::Unhandled,
        },
        0x12..=0x14 => match &insn.operands {
            Operands::ConstPool(idx) => {
                let value: String = ldc_constant(cf, *idx);
                push(stack, Expr::Const(value))
            }
            _ => LiftResult::Unhandled,
        },
        0x15..=0x19 => match &insn.operands {
            Operands::Local(idx) => {
                if op == 0x19 && *idx == 0 && has_this && !params.iter().any(|(i, _)| *i == 0) {
                    push(stack, Expr::This)
                } else {
                    push(stack, Expr::Local(local_name(*idx, params)))
                }
            }
            _ => LiftResult::Unhandled,
        },
        0x1A..=0x1D => push(stack, Expr::Local(local_name(u16::from(op - 0x1A), params))),
        0x1E..=0x21 => push(stack, Expr::Local(local_name(u16::from(op - 0x1E), params))),
        0x22..=0x25 => push(stack, Expr::Local(local_name(u16::from(op - 0x22), params))),
        0x26..=0x29 => push(stack, Expr::Local(local_name(u16::from(op - 0x26), params))),
        0x2A..=0x2D => {
            let idx: u16 = u16::from(op - 0x2A);
            if idx == 0 && has_this && !params.iter().any(|(i, _)| *i == 0) {
                push(stack, Expr::This)
            } else {
                push(stack, Expr::Local(local_name(idx, params)))
            }
        }
        0x2E..=0x35 => binary_array_load(stack),
        0x36..=0x3A => store_local(insn, stack, params),
        0x3B..=0x3E => store_indexed(stack, u16::from(op - 0x3B), params, insn.pc),
        0x3F..=0x42 => store_indexed(stack, u16::from(op - 0x3F), params, insn.pc),
        0x43..=0x46 => store_indexed(stack, u16::from(op - 0x43), params, insn.pc),
        0x47..=0x4A => store_indexed(stack, u16::from(op - 0x47), params, insn.pc),
        0x4B..=0x4E => store_indexed(stack, u16::from(op - 0x4B), params, insn.pc),
        0x4F..=0x56 => array_store(stack),
        0x57 => match stack.pop().as_ref().and_then(Expr::discarded_side_effect) {
            Some(call) => LiftResult::Statement(call),
            None => LiftResult::Pushed,
        },
        0x58 => {
            let top: Option<Expr> = stack.pop();
            stack.pop();
            match top.as_ref().and_then(Expr::discarded_side_effect) {
                Some(call) => LiftResult::Statement(call),
                None => LiftResult::Pushed,
            }
        }
        0x59 => {
            if let Some(top) = stack.last() {
                let dup: Expr = dup_clone(top);
                stack.push(dup);
            }
            LiftResult::Pushed
        }
        0x5A => dup_x1(stack),
        0x5B => dup_x2(stack),
        0x5C => dup2(stack),
        0x5D => dup2_x1(stack),
        0x5E => dup2_x2(stack),
        0x60..=0x63 => binary_op_kind(stack, "+", arith_num_kind(op)),
        0x64..=0x67 => binary_op_kind(stack, "-", arith_num_kind(op)),
        0x68..=0x6B => binary_op_kind(stack, "*", arith_num_kind(op)),
        0x6C..=0x6F => binary_op_kind(stack, "/", arith_num_kind(op)),
        0x70..=0x73 => binary_op_kind(stack, "%", arith_num_kind(op)),
        0x74..=0x77 => unary_op_kind(stack, "-", arith_num_kind(op)),
        0x78 | 0x79 => binary_op_kind(stack, "<<", shift_num_kind(op)),
        0x7A | 0x7B => binary_op_kind(stack, ">>", shift_num_kind(op)),
        0x7C | 0x7D => binary_op_kind(stack, ">>>", shift_num_kind(op)),
        0x7E | 0x7F => binary_op_kind(stack, "&", shift_num_kind(op)),
        0x80 | 0x81 => binary_op_kind(stack, "|", shift_num_kind(op)),
        0x82 | 0x83 => binary_op_kind(stack, "^", shift_num_kind(op)),
        0x84 => iinc(insn, params),
        0x85..=0x93 => cast_numeric(insn, stack),
        0x94..=0x98 => binary_op(stack, "cmp"),
        0x99..=0xA6 => conditional_branch(insn, stack),
        0xA7 | 0xC8 => {
            LiftResult::ControlFlow(format!("// goto L{}", branch_target(insn).unwrap_or(0)))
        }
        0xAC..=0xB0 => {
            let value: Expr = pop_expr(stack);
            if op == 0xAC
                && bool_return
                && let Expr::Const(c) = &value
                && let Some(b) = int_literal_as_bool(c)
            {
                return LiftResult::Statement(format!("return {b}"));
            }
            LiftResult::Statement(format!("return {}", value.render()))
        }
        0xB1 => LiftResult::Statement("return".to_string()),
        0xB2 | 0xB4 => field_get(cf, insn, stack, op == 0xB2),
        0xB3 | 0xB5 => field_put(cf, insn, stack, op == 0xB3),
        0xB6..=0xB9 => invoke(cf, insn, stack, op),
        0xBA => invoke_dynamic(cf, insn, stack, bootstraps),
        0xBB => new_object(cf, insn, stack),
        0xBC | 0xBD => new_array(cf, insn, stack),
        0xBE => array_length(stack),
        0xBF => {
            let value: Expr = pop_expr(stack);
            let rendered: String = match &value {
                Expr::Local(name) if local_is_object_typed(name) => {
                    format!("(Throwable) {}", value.render())
                }
                _ => value.render(),
            };
            LiftResult::Statement(format!("throw {rendered}"))
        }
        0xC0 => checkcast(cf, insn, stack),
        0xC1 => instance_of(cf, insn, stack),
        0xC2 => {
            stack.pop();
            LiftResult::ControlFlow("// monitorenter (synchronized)".to_string())
        }
        0xC3 => {
            stack.pop();
            LiftResult::ControlFlow("// monitorexit".to_string())
        }
        0xC5 => multi_new_array(cf, insn, stack),
        _ => LiftResult::Unhandled,
    }
}

fn multi_new_array(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::MultiANewArray { index, dimensions } = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let raw: String = bytecode::resolve_ref(cf, *index).unwrap_or_else(|| "Object".to_string());
    let element: JavaType = strip_array_dims(&raw);
    let sizes: Vec<Expr> = (0..*dimensions).map(|_| pop_expr(stack)).collect();
    let mut rendered: String = format!("new {}", element.render());
    for size in sizes.iter().rev() {
        let _ = write!(rendered, "[{}]", size.render());
    }
    push(stack, Expr::Opaque(rendered))
}

fn strip_array_dims(internal: &str) -> JavaType {
    match descriptor::parse_field(internal) {
        Some(mut ty) => {
            while let JavaType::Array(inner) = ty {
                ty = *inner;
            }
            ty
        }
        None => JavaType::Object(internal.to_string()),
    }
}

#[inline]
fn push(stack: &mut Vec<Expr>, e: Expr) -> LiftResult {
    stack.push(e);
    LiftResult::Pushed
}

fn is_category2_literal(e: &Expr) -> bool {
    let Expr::Const(c): &Expr = e else {
        return false;
    };
    let lower: String = c.to_ascii_lowercase();
    lower.ends_with('l') || lower.ends_with('d') || (c.contains('.') && !c.contains("0x"))
}

fn dup2(stack: &mut Vec<Expr>) -> LiftResult {
    match stack.last() {
        Some(top) if is_category2_literal(top) => {
            let dup: Expr = dup_clone(top);
            stack.push(dup);
            LiftResult::Pushed
        }
        Some(_) if stack.len() >= 2 => {
            let len: usize = stack.len();
            let a: Expr = dup_clone(&stack[len - 2]);
            let b: Expr = dup_clone(&stack[len - 1]);
            stack.push(a);
            stack.push(b);
            LiftResult::Pushed
        }
        Some(top) => {
            let dup: Expr = dup_clone(top);
            stack.push(dup);
            LiftResult::Pushed
        }
        None => LiftResult::Unhandled,
    }
}

fn dup_x1(stack: &mut Vec<Expr>) -> LiftResult {
    let len: usize = stack.len();
    if len < 2 {
        return LiftResult::Unhandled;
    }
    let dup: Expr = dup_clone(&stack[len - 1]);
    stack.insert(len - 2, dup);
    LiftResult::Pushed
}

fn dup_x2(stack: &mut Vec<Expr>) -> LiftResult {
    let len: usize = stack.len();
    if len < 2 {
        return LiftResult::Unhandled;
    }
    let dup: Expr = dup_clone(&stack[len - 1]);
    let cat2_under: bool = len >= 2 && is_category2_literal(&stack[len - 2]);
    let insert_at: usize = if cat2_under || len < 3 {
        len - 2
    } else {
        len - 3
    };
    stack.insert(insert_at, dup);
    LiftResult::Pushed
}

fn dup2_x1(stack: &mut Vec<Expr>) -> LiftResult {
    let len: usize = stack.len();
    if len == 0 {
        return LiftResult::Unhandled;
    }
    if is_category2_literal(&stack[len - 1]) {
        if len < 2 {
            return LiftResult::Unhandled;
        }
        let dup: Expr = dup_clone(&stack[len - 1]);
        stack.insert(len - 2, dup);
        return LiftResult::Pushed;
    }
    if len < 3 {
        return LiftResult::Unhandled;
    }
    let a: Expr = dup_clone(&stack[len - 2]);
    let b: Expr = dup_clone(&stack[len - 1]);
    stack.insert(len - 3, b);
    stack.insert(len - 3, a);
    LiftResult::Pushed
}

fn dup2_x2(stack: &mut Vec<Expr>) -> LiftResult {
    let len: usize = stack.len();
    if len == 0 {
        return LiftResult::Unhandled;
    }
    if is_category2_literal(&stack[len - 1]) {
        if len < 2 {
            return LiftResult::Unhandled;
        }
        let dup: Expr = dup_clone(&stack[len - 1]);
        let insert_at: usize = if is_category2_literal(&stack[len - 2]) || len < 3 {
            len - 2
        } else {
            len - 3
        };
        stack.insert(insert_at, dup);
        return LiftResult::Pushed;
    }
    if len < 4 {
        return LiftResult::Unhandled;
    }
    let a: Expr = dup_clone(&stack[len - 2]);
    let b: Expr = dup_clone(&stack[len - 1]);
    stack.insert(len - 4, b);
    stack.insert(len - 4, a);
    LiftResult::Pushed
}

#[inline]
fn dup_clone(e: &Expr) -> Expr {
    if expr_node_count_capped(e, MAX_DUP_EXPR_NODES) >= MAX_DUP_EXPR_NODES {
        unknown()
    } else {
        e.clone()
    }
}

const HOLE_TOKEN: &str = "?";

const HOLE_RENDER: &str = "__unresolved__";

const RECORD_ARITY_PROBE_CAP: usize = 64;

#[inline]
fn unknown() -> Expr {
    Expr::Opaque(HOLE_TOKEN.to_string())
}

#[inline]
fn pop_expr(stack: &mut Vec<Expr>) -> Expr {
    stack.pop().unwrap_or_else(unknown)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumKind {
    Int,
    Long,
    Other,
}

const fn arith_num_kind(op: u8) -> NumKind {
    match op % 4 {
        0 => NumKind::Int,
        1 => NumKind::Long,
        _ => NumKind::Other,
    }
}

const fn shift_num_kind(op: u8) -> NumKind {
    match op % 2 {
        0 => NumKind::Int,
        _ => NumKind::Long,
    }
}

fn parse_int_literal(s: &str) -> Option<i32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok().map(|v: u32| v as i32);
    }
    if s.ends_with('L') || s.ends_with('l') || s.contains('.') || s.ends_with('f') {
        return None;
    }
    s.parse::<i32>().ok()
}

fn parse_long_literal(s: &str) -> Option<i64> {
    let body: &str = s.strip_suffix('L').or_else(|| s.strip_suffix('l'))?;
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|v: u64| v as i64);
    }
    body.parse::<i64>().ok()
}

fn fold_int_binary(op: &str, a: i32, b: i32) -> Option<i32> {
    Some(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" if b != 0 && !(a == i32::MIN && b == -1) => a.wrapping_div(b),
        "%" if b != 0 && !(a == i32::MIN && b == -1) => a.wrapping_rem(b),
        "&" => a & b,
        "|" => a | b,
        "^" => a ^ b,
        "<<" => a.wrapping_shl((b & 0x1F) as u32),
        ">>" => a.wrapping_shr((b & 0x1F) as u32),
        ">>>" => (a as u32).wrapping_shr((b & 0x1F) as u32) as i32,
        _ => return None,
    })
}

fn fold_long_binary(op: &str, a: i64, b: i64) -> Option<i64> {
    Some(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" if b != 0 && !(a == i64::MIN && b == -1) => a.wrapping_div(b),
        "%" if b != 0 && !(a == i64::MIN && b == -1) => a.wrapping_rem(b),
        "&" => a & b,
        "|" => a | b,
        "^" => a ^ b,
        _ => return None,
    })
}

fn fold_long_shift(op: &str, a: i64, count: i32) -> Option<i64> {
    let s: u32 = (count & 0x3F) as u32;
    Some(match op {
        "<<" => a.wrapping_shl(s),
        ">>" => a.wrapping_shr(s),
        ">>>" => (a as u64).wrapping_shr(s) as i64,
        _ => return None,
    })
}

fn folded_binary(op: &str, kind: NumKind, lhs: &Expr, rhs: &Expr) -> Option<Expr> {
    let (Expr::Const(l), Expr::Const(r)): (&Expr, &Expr) = (lhs, rhs) else {
        return None;
    };
    match kind {
        NumKind::Int => {
            let value: i32 = fold_int_binary(op, parse_int_literal(l)?, parse_int_literal(r)?)?;
            Some(Expr::Const(value.to_string()))
        }
        NumKind::Long => {
            let a: i64 = parse_long_literal(l)?;
            let value: i64 = match op {
                "<<" | ">>" | ">>>" => fold_long_shift(op, a, parse_int_literal(r)?)?,
                _ => fold_long_binary(op, a, parse_long_literal(r)?)?,
            };
            Some(Expr::Const(format!("{value}L")))
        }
        NumKind::Other => None,
    }
}

fn folded_unary(kind: NumKind, value: &Expr) -> Option<Expr> {
    let Expr::Const(v): &Expr = value else {
        return None;
    };
    match kind {
        NumKind::Int => Some(Expr::Const(
            parse_int_literal(v)?.wrapping_neg().to_string(),
        )),
        NumKind::Long => Some(Expr::Const(format!(
            "{}L",
            parse_long_literal(v)?.wrapping_neg()
        ))),
        NumKind::Other => None,
    }
}

fn binary_op(stack: &mut Vec<Expr>, op: &'static str) -> LiftResult {
    binary_op_kind(stack, op, NumKind::Other)
}

fn binary_op_kind(stack: &mut Vec<Expr>, op: &'static str, kind: NumKind) -> LiftResult {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    if op == "cmp" {
        stack.push(Expr::Cmp {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        });
    } else if let Some(folded) = folded_binary(op, kind, &lhs, &rhs) {
        stack.push(folded);
    } else {
        stack.push(Expr::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        });
    }
    LiftResult::Pushed
}

fn unary_op_kind(stack: &mut Vec<Expr>, op: &'static str, kind: NumKind) -> LiftResult {
    let value: Expr = pop_expr(stack);
    if let Some(folded) = folded_unary(kind, &value) {
        stack.push(folded);
    } else {
        stack.push(Expr::Unary {
            op,
            value: Box::new(value),
        });
    }
    LiftResult::Pushed
}

fn binary_array_load(stack: &mut Vec<Expr>) -> LiftResult {
    let index: Expr = pop_expr(stack);
    let array: Expr = narrow_array_operand(pop_expr(stack));
    stack.push(Expr::ArrayLoad {
        array: Box::new(array),
        index: Box::new(index),
    });
    LiftResult::Pushed
}

fn array_store(stack: &mut Vec<Expr>) -> LiftResult {
    let value: Expr = pop_expr(stack);
    let index: Expr = pop_expr(stack);
    let array: Expr = narrow_array_operand(pop_expr(stack));
    if let Some(result) = try_fold_array_init(stack, &array, &index, &value) {
        return result;
    }
    LiftResult::Statement(format!(
        "{}[{}] = {}",
        array.render(),
        index.render(),
        value.render()
    ))
}

fn try_fold_array_init(
    stack: &mut [Expr],
    array: &Expr,
    index: &Expr,
    value: &Expr,
) -> Option<LiftResult> {
    let idx: usize = const_index(index)?;
    let elem_ty: String = match array {
        Expr::NewArray { ty, size } if idx == 0 => {
            let _declared: usize = const_index(size)?;
            ty.clone()
        }
        Expr::ArrayInit { ty, elements } if idx == elements.len() => ty.clone(),
        _ => return None,
    };
    let top: &mut Expr = stack.last_mut()?;
    match top {
        Expr::NewArray { ty, .. } if idx == 0 && *ty == elem_ty => {
            *top = Expr::ArrayInit {
                ty: elem_ty,
                elements: vec![value.clone()],
            };
            Some(LiftResult::Pushed)
        }
        Expr::ArrayInit { ty, elements } if *ty == elem_ty && elements.len() == idx => {
            elements.push(value.clone());
            Some(LiftResult::Pushed)
        }
        _ => None,
    }
}

fn const_index(e: &Expr) -> Option<usize> {
    match e {
        Expr::Const(s) => s.parse::<usize>().ok(),
        _ => None,
    }
}

fn signature_polymorphic_return(owner: &str, name: &str, returns: &JavaType) -> Option<String> {
    let polymorphic_owner: bool = matches!(
        owner,
        "java/lang/invoke/VarHandle" | "java/lang/invoke/MethodHandle"
    );
    if !polymorphic_owner {
        return None;
    }
    let is_poly_method: bool = match owner {
        "java/lang/invoke/MethodHandle" => matches!(name, "invoke" | "invokeExact"),
        _ => true,
    };
    if !is_poly_method || matches!(returns, JavaType::Void) {
        return None;
    }
    let rendered: String = returns.render();
    if rendered == "Object" {
        None
    } else {
        Some(rendered)
    }
}

fn store_local(insn: &Instruction, stack: &mut Vec<Expr>, params: &[(u16, String)]) -> LiftResult {
    match &insn.operands {
        Operands::Local(idx) => store_indexed(stack, *idx, params, insn.pc),
        _ => LiftResult::Unhandled,
    }
}

fn store_indexed(stack: &mut Vec<Expr>, idx: u16, params: &[(u16, String)], pc: u32) -> LiftResult {
    let value: Expr = pop_expr(stack);
    if allocation_store_is_deferred(pc) {
        return LiftResult::Elided;
    }
    LiftResult::Statement(format!("{} = {}", local_name(idx, params), value.render()))
}

fn iinc(insn: &Instruction, params: &[(u16, String)]) -> LiftResult {
    match &insn.operands {
        Operands::Iinc { index, delta } => {
            let name: String = local_name(*index, params);
            if *delta == 1 {
                LiftResult::Statement(format!("{name}++"))
            } else if *delta == -1 {
                LiftResult::Statement(format!("{name}--"))
            } else if *delta < 0 {
                LiftResult::Statement(format!("{name} -= {}", -delta))
            } else {
                LiftResult::Statement(format!("{name} += {delta}"))
            }
        }
        _ => LiftResult::Unhandled,
    }
}

fn cast_numeric(insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let ty: &str = match insn.opcode {
        0x85 | 0x8C | 0x8F => "long",
        0x86 | 0x89 | 0x90 => "float",
        0x87 | 0x8A | 0x8D => "double",
        0x88 | 0x8B | 0x8E => "int",
        0x91 => "byte",
        0x92 => "char",
        0x93 => "short",
        _ => return LiftResult::Unhandled,
    };
    let value: Expr = pop_expr(stack);
    stack.push(Expr::Cast {
        ty: ty.to_string(),
        value: Box::new(value),
    });
    LiftResult::Pushed
}

fn conditional_branch(insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let target: u32 = branch_target(insn).unwrap_or(0);
    let no_bool_arrays: BTreeMap<String, u8> = BTreeMap::new();
    let cond: String = match insn.opcode {
        0x99 => unary_or_cmp_cond(stack, "==", "== 0", &no_bool_arrays),
        0x9A => unary_or_cmp_cond(stack, "!=", "!= 0", &no_bool_arrays),
        0x9B => unary_or_cmp_cond(stack, "<", "< 0", &no_bool_arrays),
        0x9C => unary_or_cmp_cond(stack, ">=", ">= 0", &no_bool_arrays),
        0x9D => unary_or_cmp_cond(stack, ">", "> 0", &no_bool_arrays),
        0x9E => unary_or_cmp_cond(stack, "<=", "<= 0", &no_bool_arrays),
        0x9F | 0xA5 => binary_cond(stack, "=="),
        0xA0 | 0xA6 => binary_cond(stack, "!="),
        0xA1 => binary_cond(stack, "<"),
        0xA2 => binary_cond(stack, ">="),
        0xA3 => binary_cond(stack, ">"),
        0xA4 => binary_cond(stack, "<="),
        _ => "?".to_string(),
    };
    LiftResult::ControlFlow(format!("if ({cond}) goto L{target};"))
}

fn binary_cond(stack: &mut Vec<Expr>, op: &str) -> String {
    let rhs: Expr = pop_expr(stack);
    let lhs: Expr = pop_expr(stack);
    format!("{} {op} {}", lhs.render(), rhs.render())
}

fn split_member(reference: &str) -> Option<(String, String, String)> {
    let (owner_name, desc): (&str, &str) = reference.rsplit_once(':')?;
    let (owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some((owner.to_string(), name.to_string(), desc.to_string()))
}

fn field_get(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    is_static: bool,
) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    let boolean: bool = matches!(descriptor::parse_field(&desc), Some(JavaType::Boolean));
    if is_static {
        push(
            stack,
            Expr::StaticField {
                owner: descriptor::binary_to_source(&owner),
                name,
                boolean,
            },
        )
    } else {
        let receiver: Expr = stack.pop().unwrap_or(Expr::This);
        push(
            stack,
            Expr::Field {
                receiver: Box::new(receiver),
                owner,
                name,
                boolean,
            },
        )
    }
}

fn field_put(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    is_static: bool,
) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    let raw_value: Expr = pop_expr(stack);
    let value: Expr = match descriptor::parse_field(&desc) {
        Some(ty) => coerce_arg(raw_value, &ty),
        None => raw_value,
    };
    if is_static {
        let qualifier: String = if cf.this_class_name().is_ok_and(|n: &str| n == owner) {
            String::new()
        } else {
            format!("{}.", descriptor::binary_to_source(&owner))
        };
        LiftResult::Statement(format!("{qualifier}{name} = {}", value.render()))
    } else {
        let receiver: Expr = stack.pop().unwrap_or(Expr::This);
        let lhs: String = render_field_access(&receiver, &owner, &name);
        LiftResult::Statement(format!("{lhs} = {}", value.render()))
    }
}

fn invoke(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>, op: u8) -> LiftResult {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) => *i,
        Operands::InvokeInterface { index, .. } => *index,
        _ => return LiftResult::Unhandled,
    };
    let Some(reference): Option<String> = bytecode::resolve_ref(cf, idx) else {
        return LiftResult::Unhandled;
    };
    let Some((owner, name, desc)): Option<(String, String, String)> = split_member(&reference)
    else {
        return LiftResult::Unhandled;
    };
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(&desc) else {
        return LiftResult::Unhandled;
    };
    let argc: usize = parsed.params.len();
    if stack.len() < argc {
        return LiftResult::Unhandled;
    }
    let raw_args: Vec<Expr> = stack.split_off(stack.len() - argc);
    let args: Vec<Expr> = raw_args
        .into_iter()
        .zip(parsed.params.iter())
        .map(|(a, want): (Expr, &JavaType)| coerce_arg(a, want))
        .collect();
    let is_static: bool = op == 0xB8;
    let receiver: Option<Expr> = if is_static {
        None
    } else {
        Some(stack.pop().unwrap_or(Expr::This))
    };

    if name == "<init>" {
        let ctor_args: Vec<String> = args.iter().map(Expr::render).collect();
        let joined: String = ctor_args.join(", ");
        if let Some(internal) = deferred_allocation_class(insn.pc)
            && let Some(Expr::Local(target)) = receiver.as_ref()
        {
            let allocated: String = descriptor::binary_to_source(&internal);
            return LiftResult::Statement(format!(
                "{target} = {}",
                allocation_expression(&allocated, &ctor_args)
            ));
        }
        match receiver {
            Some(Expr::New(ty)) => {
                let folded: Expr = Expr::Opaque(allocation_expression(&ty, &ctor_args));
                if matches!(stack.last(), Some(Expr::New(under)) if *under == ty) {
                    stack.pop();
                    stack.push(folded);
                    return LiftResult::Pushed;
                }
                return LiftResult::Statement(folded.render());
            }
            Some(Expr::This) | None => {
                let is_self_delegate: bool = cf.this_class_name().is_ok_and(|n: &str| n == owner);
                let kw: &str = if is_self_delegate { "this" } else { "super" };
                return LiftResult::Statement(format!(
                    "{kw}({joined}) /* {} */",
                    descriptor::binary_to_source(&owner)
                ));
            }
            Some(other) => {
                return LiftResult::Statement(format!("{}.<init>({joined})", other.render()));
            }
        }
    }

    let projection: Option<ApiOutlineProjection> = is_static
        .then(|| api_outline_projection(&owner, &name, &desc))
        .flatten();
    let projected_owner: &str = projection
        .as_ref()
        .map_or(owner.as_str(), |projected: &ApiOutlineProjection| {
            projected.owner.as_str()
        });
    let projected_name: &str = projection
        .as_ref()
        .map_or(name.as_str(), |projected: &ApiOutlineProjection| {
            projected.name.as_str()
        });
    let owner_src: String = descriptor::binary_to_source(projected_owner);
    let virtual_dispatch: bool = matches!(op, 0xB6 | 0xB9);
    let typed_receiver: Option<Expr> =
        receiver.map(|r: Expr| narrow_invoke_receiver(r, &owner_src, virtual_dispatch));
    let polymorphic_cast: Option<String> =
        signature_polymorphic_return(&owner, &name, &parsed.returns);
    let call: Expr = Expr::Invoke {
        receiver: typed_receiver.map(Box::new),
        owner: owner_src,
        method: projected_name.to_owned(),
        args,
        returns_bool: matches!(parsed.returns, JavaType::Boolean),
    };
    if matches!(parsed.returns, JavaType::Void) {
        LiftResult::Statement(call.render())
    } else {
        let pushed: Expr = match polymorphic_cast {
            Some(ty) => Expr::Cast {
                ty,
                value: Box::new(call),
            },
            None => call,
        };
        stack.push(pushed);
        LiftResult::Pushed
    }
}

fn invoke_dynamic(
    cf: &ClassFile,
    insn: &Instruction,
    stack: &mut Vec<Expr>,
    bootstraps: &[crate::attributes::BootstrapMethod],
) -> LiftResult {
    let idx: u16 = match &insn.operands {
        Operands::ConstPool(i) | Operands::InvokeDynamic(i) => *i,
        _ => return push(stack, Expr::Opaque("lambda$()".to_string())),
    };
    let Some(indy): Option<&crate::classfile::ConstantPoolEntry> =
        cf.constant_pool.get(usize::from(idx))
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let crate::classfile::ConstantPoolEntry::InvokeDynamic {
        bootstrap_method_attr_index,
        name_and_type_index,
    } = indy
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let Some((indy_name, indy_desc)): Option<(String, String)> =
        name_and_type_parts(cf, *name_and_type_index)
    else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let Some(parsed): Option<MethodDescriptor> = descriptor::parse_method(&indy_desc) else {
        return push(stack, Expr::Opaque("lambda$()".to_string()));
    };
    let argc: usize = parsed.params.len();
    let popped: usize = argc.min(stack.len());
    let args: Vec<Expr> = stack.split_off(stack.len() - popped);

    let bsm: Option<&crate::attributes::BootstrapMethod> =
        bootstraps.get(usize::from(*bootstrap_method_attr_index));
    let bsm_name: Option<String> = bsm.and_then(|b| method_handle_ref_name(cf, b.method_ref_index));

    crate::debug::dbg_kv("indy", || {
        format!(
            "name={indy_name} desc={indy_desc} bsm_attr_index={} bootstrap={} args={argc}",
            bootstrap_method_attr_index,
            bsm_name.as_deref().unwrap_or("<unresolved>")
        )
    });

    if matches!(
        bsm_name.as_deref(),
        Some("makeConcatWithConstants" | "makeConcat")
    ) {
        let recipe: Option<String> = bsm
            .filter(|_| bsm_name.as_deref() == Some("makeConcatWithConstants"))
            .and_then(|b| b.arguments.first())
            .and_then(|&a| bootstrap_string_arg(cf, a));
        let folded: Expr = fold_string_concat(recipe.as_deref(), &args);
        return push(stack, folded);
    }

    if matches!(parsed.returns, JavaType::Object(_)) {
        let impl_handle: Option<MethodHandleRef> = bsm
            .and_then(|b| b.arguments.get(1).copied())
            .and_then(|a| method_handle_full(cf, a));
        let sam_arity: Option<usize> = bsm
            .and_then(|b| b.arguments.first().copied())
            .and_then(|a| method_type_arity(cf, a));
        let sam_params: Option<Vec<JavaType>> = bsm
            .and_then(|b| b.arguments.first().copied())
            .and_then(|a| method_type_params(cf, a));
        if let Some(handle) = impl_handle {
            let lambda: String =
                lower_indy_target(&handle, sam_arity, sam_params.as_deref(), &args);
            let typed: String = sam_typed_lambda(&lambda, &parsed.returns);
            return push(stack, Expr::Opaque(typed));
        }
        return push(stack, Expr::Opaque(format!("{indy_name}$lambda")));
    }
    push(stack, Expr::Opaque(format!("{indy_name}()")))
}

struct MethodHandleRef {
    kind: u8,
    owner: String,
    name: String,
    descriptor: String,
}

fn lower_indy_target(
    handle: &MethodHandleRef,
    sam_arity: Option<usize>,
    sam_params: Option<&[JavaType]>,
    captured: &[Expr],
) -> String {
    let owner_src: String = descriptor::binary_to_source(&handle.owner);
    let is_synthetic_lambda: bool = handle.name.starts_with("lambda$");
    if !is_synthetic_lambda {
        if handle.kind == 8 {
            return format!("{owner_src}::new");
        }
        if let Some(lambda) = expand_unbound_method_ref(handle, &owner_src, sam_arity, captured) {
            return lambda;
        }
        if let Some(lambda) = expand_primitive_method_ref(handle, &owner_src, sam_params, captured)
        {
            return lambda;
        }
        return format!("{owner_src}::{}", handle.name);
    }
    let impl_params: Vec<JavaType> = descriptor::parse_method(&handle.descriptor)
        .map(|m: MethodDescriptor| m.params)
        .unwrap_or_default();
    let impl_arity: usize = impl_params.len();
    let captured_count: usize = captured.len().min(impl_arity);
    let lambda_arity: usize =
        sam_arity.unwrap_or_else(|| impl_arity.saturating_sub(captured_count));
    let lambda_params: Vec<String> = (0..lambda_arity).map(|i: usize| format!("p{i}")).collect();
    let mut call_args: Vec<String> = captured
        .iter()
        .take(captured_count)
        .map(Expr::render)
        .collect();
    for (i, param) in lambda_params.iter().enumerate() {
        match impl_params.get(captured_count + i) {
            Some(ty) if needs_lambda_cast(ty) => {
                call_args.push(format!("({}) {param}", ty.render()));
            }
            _ => call_args.push(param.clone()),
        }
    }
    let param_list: String = if lambda_arity == 1 {
        lambda_params[0].clone()
    } else {
        format!("({})", lambda_params.join(", "))
    };
    format!(
        "{param_list} -> {owner_src}.{}({})",
        recompile_safe_method_name(&handle.name),
        call_args.join(", ")
    )
}

fn expand_unbound_method_ref(
    handle: &MethodHandleRef,
    owner_src: &str,
    sam_arity: Option<usize>,
    captured: &[Expr],
) -> Option<String> {
    if !matches!(handle.kind, 5 | 9) || !captured.is_empty() {
        return None;
    }
    let impl_params: Vec<JavaType> = descriptor::parse_method(&handle.descriptor)
        .map(|m: MethodDescriptor| m.params)
        .unwrap_or_default();
    let sam: usize = sam_arity?;
    if sam != impl_params.len() + 1 {
        return None;
    }
    let lambda_params: Vec<String> = (0..sam).map(|i: usize| format!("p{i}")).collect();
    let receiver: &str = lambda_params.first()?;
    let mut call_args: Vec<String> = Vec::with_capacity(impl_params.len());
    for (i, param) in lambda_params.iter().skip(1).enumerate() {
        match impl_params.get(i) {
            Some(ty) if needs_lambda_cast(ty) => {
                call_args.push(format!("({}) {param}", ty.render()));
            }
            _ => call_args.push(param.clone()),
        }
    }
    let param_list: String = if sam == 1 {
        receiver.to_string()
    } else {
        format!("({})", lambda_params.join(", "))
    };
    Some(format!(
        "{param_list} -> (({owner_src}) {receiver}).{}({})",
        handle.name,
        call_args.join(", ")
    ))
}

fn is_java_lang_object(ty: &JavaType) -> bool {
    matches!(ty, JavaType::Object(name) if name == "java/lang/Object" || name == "Ljava/lang/Object;")
}

fn needs_lambda_cast(ty: &JavaType) -> bool {
    !is_java_lang_object(ty)
}

const fn boxed_wrapper(ty: &JavaType) -> Option<&'static str> {
    Some(match ty {
        JavaType::Int => "Integer",
        JavaType::Long => "Long",
        JavaType::Double => "Double",
        JavaType::Float => "Float",
        JavaType::Short => "Short",
        JavaType::Byte => "Byte",
        JavaType::Char => "Character",
        JavaType::Boolean => "Boolean",
        _ => return None,
    })
}

fn sam_param_is_object(sam_params: Option<&[JavaType]>, i: usize) -> bool {
    sam_params
        .and_then(|p: &[JavaType]| p.get(i))
        .is_none_or(is_java_lang_object)
}

fn expand_primitive_method_ref(
    handle: &MethodHandleRef,
    owner_src: &str,
    sam_params: Option<&[JavaType]>,
    captured: &[Expr],
) -> Option<String> {
    let impl_params: Vec<JavaType> = descriptor::parse_method(&handle.descriptor)
        .map(|m: MethodDescriptor| m.params)
        .unwrap_or_default();
    let bound_receiver: bool = matches!(handle.kind, 5 | 9) && captured.len() == 1;
    let is_static: bool = handle.kind == 6 && captured.is_empty();
    if !bound_receiver && !is_static {
        return None;
    }
    let needs_box: bool = impl_params
        .iter()
        .enumerate()
        .any(|(i, ty): (usize, &JavaType)| {
            boxed_wrapper(ty).is_some() && sam_param_is_object(sam_params, i)
        });
    if !needs_box {
        return None;
    }
    let lambda_params: Vec<String> = (0..impl_params.len())
        .map(|i: usize| format!("p{i}"))
        .collect();
    let mut call_args: Vec<String> = Vec::with_capacity(impl_params.len());
    for (i, param) in lambda_params.iter().enumerate() {
        let target: &JavaType = &impl_params[i];
        if !sam_param_is_object(sam_params, i) {
            call_args.push(param.clone());
        } else if let Some(wrapper) = boxed_wrapper(target) {
            call_args.push(format!("({wrapper}) {param}"));
        } else if needs_lambda_cast(target) {
            call_args.push(format!("({}) {param}", target.render()));
        } else {
            call_args.push(param.clone());
        }
    }
    let param_list: String = if lambda_params.len() == 1 {
        lambda_params[0].clone()
    } else {
        format!("({})", lambda_params.join(", "))
    };
    let target_expr: String = if bound_receiver {
        captured[0].render()
    } else {
        owner_src.to_string()
    };
    Some(format!(
        "{param_list} -> {target_expr}.{}({})",
        handle.name,
        call_args.join(", ")
    ))
}

fn sam_typed_lambda(lambda: &str, sam_ty: &JavaType) -> String {
    let is_lambda_form: bool = lambda.contains("->") || lambda.contains("::");
    if !is_lambda_form || is_java_lang_object(sam_ty) {
        return lambda.to_string();
    }
    let JavaType::Object(_) = sam_ty else {
        return lambda.to_string();
    };
    format!("({}) {lambda}", sam_ty.render())
}

fn method_handle_full(cf: &ClassFile, index: u16) -> Option<MethodHandleRef> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    let crate::classfile::ConstantPoolEntry::MethodHandle {
        reference_kind,
        reference_index,
    } = entry
    else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *reference_index)?;
    let (owner_name, desc): (&str, &str) = reference.rsplit_once(':')?;
    let (owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(MethodHandleRef {
        kind: *reference_kind,
        owner: owner.to_string(),
        name: name.to_string(),
        descriptor: desc.to_string(),
    })
}

fn method_type_arity(cf: &ClassFile, index: u16) -> Option<usize> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    let crate::classfile::ConstantPoolEntry::MethodType { descriptor_index } = entry else {
        return None;
    };
    let desc: &str = cf.utf8_at(*descriptor_index).ok()?;
    descriptor::parse_method(desc).map(|m: MethodDescriptor| m.params.len())
}

fn method_type_params(cf: &ClassFile, index: u16) -> Option<Vec<JavaType>> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    let crate::classfile::ConstantPoolEntry::MethodType { descriptor_index } = entry else {
        return None;
    };
    let desc: &str = cf.utf8_at(*descriptor_index).ok()?;
    descriptor::parse_method(desc).map(|m: MethodDescriptor| m.params)
}

fn name_and_type_parts(cf: &ClassFile, index: u16) -> Option<(String, String)> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    if let crate::classfile::ConstantPoolEntry::NameAndType {
        name_index,
        descriptor_index,
    } = entry
    {
        let name: String = cf.utf8_at(*name_index).ok()?.to_string();
        let desc: String = cf.utf8_at(*descriptor_index).ok()?.to_string();
        Some((name, desc))
    } else {
        None
    }
}

fn method_handle_ref_name(cf: &ClassFile, index: u16) -> Option<String> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    let crate::classfile::ConstantPoolEntry::MethodHandle {
        reference_index, ..
    } = entry
    else {
        return None;
    };
    let reference: String = bytecode::resolve_ref(cf, *reference_index)?;
    let (owner_name, _desc): (&str, &str) = reference.rsplit_once(':')?;
    let (_owner, name): (&str, &str) = owner_name.rsplit_once('.')?;
    Some(name.to_string())
}

fn bootstrap_string_arg(cf: &ClassFile, index: u16) -> Option<String> {
    let entry: &crate::classfile::ConstantPoolEntry = cf.constant_pool.get(usize::from(index))?;
    if let crate::classfile::ConstantPoolEntry::String { utf8_index } = entry {
        cf.utf8_at(*utf8_index).ok().map(str::to_string)
    } else {
        None
    }
}

fn fold_string_concat(recipe: Option<&str>, args: &[Expr]) -> Expr {
    let mut pieces: Vec<String> = Vec::new();
    match recipe {
        Some(r) => {
            let mut arg_iter: std::slice::Iter<'_, Expr> = args.iter();
            let mut literal: String = String::new();
            for ch in r.chars() {
                match ch {
                    '\u{0001}' => {
                        if !literal.is_empty() {
                            pieces.push(bytecode::escape_java_string(&literal));
                            literal.clear();
                        }
                        if let Some(a) = arg_iter.next() {
                            pieces.push(a.render());
                        }
                    }
                    '\u{0002}' => {}
                    c => literal.push(c),
                }
            }
            if !literal.is_empty() {
                pieces.push(bytecode::escape_java_string(&literal));
            }
        }
        None => pieces.extend(args.iter().map(Expr::render)),
    }
    if pieces.is_empty() {
        return Expr::Const("\"\"".to_string());
    }
    if pieces.first().is_none_or(|p: &String| !p.starts_with('"')) {
        pieces.insert(0, "\"\"".to_string());
    }
    Expr::Opaque(format!("({})", pieces.join(" + ")))
}

fn new_object(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let Some(name): Option<String> = bytecode::resolve_ref(cf, *idx) else {
        return LiftResult::Unhandled;
    };
    push(stack, Expr::New(descriptor::binary_to_source(&name)))
}

fn ldc_constant(cf: &ClassFile, idx: u16) -> String {
    let pool_idx: usize = usize::from(idx);
    if let Some(crate::classfile::ConstantPoolEntry::Class { .. }) = cf.constant_pool.get(pool_idx)
        && let Ok(name) = cf.class_name(idx)
    {
        let src: String = descriptor::binary_to_source(name);
        return format!("{src}.class");
    }
    bytecode::resolve_ref(cf, idx).unwrap_or_else(|| "/*ldc*/0".to_string())
}

fn new_array(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let size: Expr = pop_expr(stack);
    let ty: String = match (&insn.operands, insn.opcode) {
        (Operands::NewArray(code), _) => primitive_array_type(*code).to_string(),
        (Operands::ConstPool(idx), _) => bytecode::resolve_ref(cf, *idx)
            .map(|n| descriptor::binary_to_source(&n))
            .unwrap_or_else(|| "Object".to_string()),
        _ => "Object".to_string(),
    };
    push(
        stack,
        Expr::NewArray {
            ty,
            size: Box::new(size),
        },
    )
}

const fn primitive_array_type(code: u8) -> &'static str {
    match code {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => "Object",
    }
}

fn narrow_array_operand(arr: Expr) -> Expr {
    let Expr::Local(name) = &arr else {
        return arr;
    };
    let Some(ty): Option<String> = object_local_array_cast(name) else {
        return arr;
    };
    Expr::Cast {
        ty,
        value: Box::new(arr),
    }
}

fn array_length(stack: &mut Vec<Expr>) -> LiftResult {
    let arr: Expr = narrow_array_operand(pop_expr(stack));
    push(stack, Expr::ArrayLength(Box::new(arr)))
}

fn checkcast(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let ty: String = bytecode::resolve_ref(cf, *idx)
        .map(|n| descriptor::binary_to_source(&n))
        .unwrap_or_else(|| "Object".to_string());
    let value: Expr = pop_expr(stack);
    stack.push(Expr::Cast {
        ty,
        value: Box::new(value),
    });
    LiftResult::Pushed
}

fn instance_of(cf: &ClassFile, insn: &Instruction, stack: &mut Vec<Expr>) -> LiftResult {
    let Operands::ConstPool(idx) = &insn.operands else {
        return LiftResult::Unhandled;
    };
    let ty: String = bytecode::resolve_ref(cf, *idx)
        .map(|n| descriptor::binary_to_source(&n))
        .unwrap_or_else(|| "Object".to_string());
    let value: Expr = pop_expr(stack);
    stack.push(Expr::InstanceOf {
        value: Box::new(value),
        ty,
    });
    LiftResult::Pushed
}

pub fn decompile_classfile_bytes(bytes: &[u8]) -> Result<DecompiledClass> {
    let cf: ClassFile = crate::classfile::parse(bytes)?;
    Ok(decompile_class(&cf))
}

#[must_use]
pub fn decompile_class_with_inners(
    cf: &ClassFile,
    inners: &std::collections::BTreeMap<String, ClassFile>,
) -> DecompiledClass {
    crate::name_disambig::ensure_writable_identifier_scope(
        declared_identifiers(std::iter::once(cf).chain(inners.values())),
        || decompile_class_with_inners_scoped(cf, inners),
    )
}

fn declared_identifiers<'a>(
    classes: impl Iterator<Item = &'a ClassFile>,
) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for class in classes {
        if let Ok(binary) = class.this_class_name() {
            for segment in binary.rsplit('/').take(1).flat_map(|s: &str| s.split('$')) {
                names.insert(segment.to_owned());
            }
        }
        for method in &class.methods {
            if let Ok(name) = class.utf8_at(method.name_index) {
                names.insert(name.to_owned());
            }
        }
        for field in &class.fields {
            if let Ok(name) = class.utf8_at(field.name_index) {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

fn decompile_class_with_inners_scoped(
    cf: &ClassFile,
    inners: &std::collections::BTreeMap<String, ClassFile>,
) -> DecompiledClass {
    let api_outlines: BTreeMap<ApiOutlineKey, ApiOutlineProjection> =
        api_outline_plan(std::iter::once(cf).chain(inners.values()));
    let anon: BTreeMap<String, ClassFile> = inners
        .iter()
        .filter_map(|(key, inner): (&String, &ClassFile)| {
            let internal: &str = key.strip_suffix(".class")?;
            is_anonymous_inner_name(internal)
                .then(|| (descriptor::binary_to_source(internal), inner.clone()))
        })
        .collect();
    let record_arities: BTreeMap<String, usize> = inners
        .iter()
        .filter_map(|(key, inner): (&String, &ClassFile)| {
            let internal: &str = key.strip_suffix(".class")?;
            let structure: crate::attributes::ClassStructure = crate::attributes::analyze(inner);
            structure
                .is_record
                .then(|| (internal.to_string(), structure.record_components.len()))
        })
        .collect();
    let mut enum_constants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut switchmaps: BTreeMap<String, BTreeMap<i32, String>> = BTreeMap::new();
    for source in std::iter::once(cf).chain(inners.values()) {
        if source.access_flags & ACC_ENUM != 0
            && let Ok(name) = source.this_class_name()
        {
            enum_constants.insert(name.to_string(), enum_constant_order(source));
        }
        for (field_ref, mapping) in switchmap_inversions(source) {
            switchmaps.entry(field_ref).or_default().extend(mapping);
        }
    }
    let mut d: DecompiledClass = with_enum_metadata(enum_constants, switchmaps, || {
        with_record_arities(record_arities, || {
            with_anon_inners(anon, || {
                with_api_outline_projections(api_outlines, || decompile_class(cf))
            })
        })
    });
    let inner_stubs: String = build_inner_class_stubs(cf, inners);
    if !inner_stubs.is_empty()
        && let Some(pos) = d.source.rfind('}')
    {
        d.source.insert_str(pos, &inner_stubs);
    }
    d
}

fn is_anonymous_inner_name(internal: &str) -> bool {
    internal
        .rsplit_once('$')
        .is_some_and(|(_, tail): (&str, &str)| {
            !tail.is_empty() && tail.bytes().all(|b: u8| b.is_ascii_digit())
        })
}

const fn default_return_expr(ty: &JavaType) -> &'static str {
    match ty {
        JavaType::Void => "",
        JavaType::Long => "return 0L;",
        JavaType::Float => "return 0.0f;",
        JavaType::Double => "return 0.0;",
        JavaType::Boolean => "return false;",
        JavaType::Byte | JavaType::Short | JavaType::Char | JavaType::Int => "return 0;",
        JavaType::Object(_) | JavaType::Array(_) => "return null;",
    }
}

fn super_ctor_call(
    inner_cf: &ClassFile,
    inners: &std::collections::BTreeMap<String, ClassFile>,
) -> Option<String> {
    let super_name: &str = inner_cf.class_name(inner_cf.super_class).ok()?;
    let super_cf: &ClassFile = inners.get(&format!("{super_name}.class"))?;
    let ctors: Vec<&MethodInfo> = super_cf
        .methods
        .iter()
        .filter(|m| {
            super_cf
                .utf8_at(m.name_index)
                .is_ok_and(|n: &str| n == "<init>")
        })
        .collect();
    if ctors.is_empty() {
        return None;
    }
    let has_noarg: bool = ctors.iter().any(|m| {
        super_cf
            .utf8_at(m.descriptor_index)
            .ok()
            .and_then(descriptor::parse_method)
            .is_some_and(|d: MethodDescriptor| d.params.is_empty())
    });
    if has_noarg {
        return None;
    }
    let chosen: &MethodInfo = ctors.first()?;
    let desc: &str = super_cf.utf8_at(chosen.descriptor_index).ok()?;
    let parsed: MethodDescriptor = descriptor::parse_method(desc)?;
    let args: Vec<&str> = parsed
        .params
        .iter()
        .map(|p: &JavaType| default_value_literal(p))
        .collect();
    Some(format!("super({});", args.join(", ")))
}

const fn default_value_literal(ty: &JavaType) -> &'static str {
    match ty {
        JavaType::Boolean => "false",
        JavaType::Long => "0L",
        JavaType::Float => "0.0f",
        JavaType::Double => "0.0",
        JavaType::Byte | JavaType::Short | JavaType::Char | JavaType::Int => "0",
        JavaType::Object(_) | JavaType::Array(_) => "null",
        JavaType::Void => "",
    }
}

fn render_inner_method_stub(
    annotation_renderer: &mut crate::attributes::DeclarationAnnotationRenderer,
    inner_cf: &ClassFile,
    method: &MethodInfo,
    simple: &str,
    super_call: Option<&str>,
    annotation_default: Option<&str>,
    class_signature: Option<&crate::signature::RecoveredClassSignature>,
) -> Option<String> {
    let is_enum: bool = inner_cf.access_flags & ACC_ENUM != 0;
    let is_interface: bool = inner_cf.access_flags & ACC_INTERFACE != 0;
    if is_bridge_method(method) {
        return None;
    }
    if method.access_flags & ACC_SYNTHETIC != 0 {
        return None;
    }
    let name: &str = inner_cf.utf8_at(method.name_index).ok()?;
    if name == "<clinit>" {
        return None;
    }
    if is_interface && name == "<init>" {
        return None;
    }
    if is_enum && is_generated_enum_method(inner_cf, method) {
        return None;
    }
    let desc: &str = inner_cf.utf8_at(method.descriptor_index).ok()?;
    let parsed: MethodDescriptor = descriptor::parse_method(desc)?;
    let generic_signature: Option<crate::signature::RecoveredMethodSignature> =
        crate::signature::recover_method(inner_cf, method, class_signature);
    let is_bodyless: bool = method.access_flags & (ACC_ABSTRACT | ACC_NATIVE) != 0 && !is_enum;
    let is_static: bool = method.access_flags & ACC_STATIC != 0;
    let is_varargs: bool = method.access_flags & ACC_VARARGS != 0;
    let mut kw_flags: u16 = method.access_flags & !(ACC_VOLATILE | ACC_TRANSIENT | ACC_BRIDGE);
    if !is_bodyless {
        kw_flags &= !ACC_ABSTRACT;
    }
    let kw: String = member_access_keywords(kw_flags);
    let params: String = parsed
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let ty: String = generic_signature.as_ref().map_or_else(
                || render_parameter_type(p, is_varargs && i + 1 == parsed.params.len()),
                |signature: &crate::signature::RecoveredMethodSignature| {
                    render_generic_parameter_type(
                        &signature.parameters[i],
                        is_varargs && i + 1 == parsed.params.len(),
                    )
                },
            );
            format!("{ty} arg{i}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let prefix: &str = "        ";
    let kw_str: String = if kw.is_empty() {
        String::new()
    } else {
        format!("{kw} ")
    };
    let default_kw: &str = if is_interface && !is_bodyless && !is_static {
        "default "
    } else {
        ""
    };
    let type_parameters: String =
        generic_signature
            .as_ref()
            .map_or_else(String::new, |signature| {
                if signature.type_parameters.is_empty() {
                    String::new()
                } else {
                    format!("{} ", signature.type_parameters)
                }
            });
    let throws_clause: String = generic_signature.as_ref().map_or_else(
        || method_throws_clause(inner_cf, method),
        |signature: &crate::signature::RecoveredMethodSignature| {
            if signature.throws.is_empty() {
                method_throws_clause(inner_cf, method)
            } else {
                format!(" throws {}", signature.throws.join(", "))
            }
        },
    );
    let sig: String = if name == "<init>" {
        format!("{prefix}{kw_str}{type_parameters}{simple}({params}){throws_clause}")
    } else {
        let ret: String = generic_signature.as_ref().map_or_else(
            || parsed.returns.render(),
            |signature: &crate::signature::RecoveredMethodSignature| signature.result.clone(),
        );
        let emit_name: String = recompile_safe_method_name(name);
        format!(
            "{prefix}{kw_str}{default_kw}{type_parameters}{ret} {emit_name}({params}){throws_clause}"
        )
    };
    let declaration: String = if is_bodyless || annotation_default.is_some() {
        let default_value: String =
            annotation_default.map_or_else(String::new, |value: &str| format!(" default {value}"));
        format!("{sig}{default_value};")
    } else if name == "<init>" {
        super_call.map_or_else(
            || format!("{sig} {{}}"),
            |call: &str| format!("{sig} {{ {call} }}"),
        )
    } else {
        let body: &str = default_return_expr(&parsed.returns);
        if body.is_empty() {
            format!("{sig} {{}}")
        } else {
            format!("{sig} {{ {body} }}")
        }
    };
    let annotations: String =
        render_member_annotations(annotation_renderer, inner_cf, &method.attributes, prefix);
    Some(format!("{annotations}{declaration}"))
}

fn render_inner_field_stub(
    annotation_renderer: &mut crate::attributes::DeclarationAnnotationRenderer,
    inner_cf: &ClassFile,
    field: &FieldInfo,
    is_enum: bool,
    class_signature: Option<&crate::signature::RecoveredClassSignature>,
) -> Option<String> {
    if field.access_flags & ACC_SYNTHETIC != 0 {
        return None;
    }
    if is_enum && field.access_flags & ACC_ENUM != 0 {
        return None;
    }
    let name: &str = inner_cf.utf8_at(field.name_index).ok()?;
    if name == "$VALUES" || name.starts_with("$") {
        return None;
    }
    let desc: &str = inner_cf.utf8_at(field.descriptor_index).ok()?;
    let ty: JavaType = descriptor::parse_field(desc)?;
    let rendered_type: String = crate::signature::recover_field(inner_cf, field, class_signature)
        .unwrap_or_else(|| ty.render());
    let kw: String = member_access_keywords(field.access_flags & !(ACC_VOLATILE | ACC_TRANSIENT));
    let kw_str: String = if kw.is_empty() {
        String::new()
    } else {
        format!("{kw} ")
    };
    let init: String = constant_value_initializer(inner_cf, field, &ty).map_or_else(
        || {
            if field.access_flags & ACC_FINAL != 0 {
                format!(" = {}", java_type_default(&ty))
            } else {
                String::new()
            }
        },
        |value: String| format!(" = {value}"),
    );
    let declaration: String = format!("        {kw_str}{rendered_type} {name}{init};");
    let annotations: String =
        render_member_annotations(annotation_renderer, inner_cf, &field.attributes, "        ");
    Some(format!("{annotations}{declaration}"))
}

const fn java_type_default(ty: &JavaType) -> &'static str {
    match ty {
        JavaType::Boolean => "false",
        JavaType::Byte | JavaType::Char | JavaType::Int | JavaType::Short => "0",
        JavaType::Long => "0L",
        JavaType::Float => "0.0f",
        JavaType::Double => "0.0",
        JavaType::Void | JavaType::Object(_) | JavaType::Array(_) => "null",
    }
}

fn anon_capture_field_order(anon_cf: &ClassFile) -> Vec<String> {
    let Some(ctor): Option<&MethodInfo> = anon_cf.methods.iter().find(|m: &&MethodInfo| {
        anon_cf
            .utf8_at(m.name_index)
            .is_ok_and(|n: &str| n == "<init>")
    }) else {
        return Vec::new();
    };
    let MethodCode::Decoded(code): MethodCode = find_code(anon_cf, ctor) else {
        return Vec::new();
    };
    let Ok(insns): Result<Vec<Instruction>> = disassemble(&code.code) else {
        return Vec::new();
    };
    let mut order: Vec<String> = Vec::new();
    for insn in &insns {
        if insn.opcode != 0xB5 {
            continue;
        }
        let Operands::ConstPool(idx) = &insn.operands else {
            continue;
        };
        let Some(reference): Option<String> = bytecode::resolve_ref(anon_cf, *idx) else {
            continue;
        };
        let field: &str = reference
            .rsplit_once(':')
            .map_or(reference.as_str(), |(member, _): (&str, &str)| member);
        let simple: &str = field.rsplit('.').next().unwrap_or(field);
        if simple.starts_with("val$") && !order.iter().any(|f: &String| f == simple) {
            order.push(simple.to_string());
        }
    }
    order
}

fn render_anonymous_class(anon_cf: &ClassFile, captured_args: &[String]) -> Option<String> {
    let generic_class: Option<crate::signature::RecoveredClassSignature> =
        crate::signature::recover_class(anon_cf);
    let super_name: Option<String> = (anon_cf.super_class != 0)
        .then(|| {
            anon_cf
                .class_name(anon_cf.super_class)
                .ok()
                .map(str::to_string)
        })
        .flatten();
    let supertype: String = match anon_cf.interfaces.first() {
        Some(&iface) => generic_class
            .as_ref()
            .and_then(|signature: &crate::signature::RecoveredClassSignature| {
                signature.interfaces.first().cloned()
            })
            .or_else(|| {
                anon_cf
                    .class_name(iface)
                    .ok()
                    .map(descriptor::binary_to_source)
            })?,
        None => match super_name.as_deref() {
            Some("java/lang/Object") | None => "Object".to_string(),
            Some(other) => generic_class.as_ref().map_or_else(
                || descriptor::binary_to_source(other),
                |signature: &crate::signature::RecoveredClassSignature| {
                    signature.superclass.clone()
                },
            ),
        },
    };
    let capture_order: Vec<String> = anon_capture_field_order(anon_cf);
    let capture_map: BTreeMap<String, String> = capture_order
        .iter()
        .zip(captured_args.iter())
        .map(|(field, arg): (&String, &String)| (field.clone(), arg.clone()))
        .collect();
    let is_enum: bool = anon_cf.access_flags & ACC_ENUM != 0;
    let mut annotation_renderer: crate::attributes::DeclarationAnnotationRenderer =
        crate::attributes::DeclarationAnnotationRenderer::new(anon_cf);
    let mut members: Vec<String> = Vec::new();
    for field in &anon_cf.fields {
        let name: &str = anon_cf.utf8_at(field.name_index).unwrap_or("");
        if name.starts_with("val$") || name.starts_with("this$") {
            continue;
        }
        if let Some(line) = render_inner_field_stub(
            &mut annotation_renderer,
            anon_cf,
            field,
            is_enum,
            generic_class.as_ref(),
        ) {
            members.push(line);
        }
    }
    for method in &anon_cf.methods {
        let name: &str = anon_cf.utf8_at(method.name_index).unwrap_or("");
        if name == "<init>" || name == "<clinit>" {
            continue;
        }
        if is_bridge_method(method) || method.access_flags & ACC_SYNTHETIC != 0 {
            continue;
        }
        let rendered: RenderedMethod = render_method(
            anon_cf,
            method,
            &supertype,
            false,
            None,
            generic_class.as_ref(),
        );
        let annotations: String = render_member_annotations(
            &mut annotation_renderer,
            anon_cf,
            &method.attributes,
            "    ",
        );
        let body: String = substitute_captures(&rendered.text, &capture_map);
        members.push(format!("{annotations}{body}"));
    }
    let mut out: String = format!("new {supertype}() {{\n");
    for member in &members {
        for line in member.lines() {
            let _ = writeln!(out, "    {line}");
        }
    }
    out.push('}');
    Some(out)
}

fn substitute_captures(text: &str, capture_map: &BTreeMap<String, String>) -> String {
    let mut out: String = text.to_string();
    for (field, arg) in capture_map {
        out = out.replace(&format!("this.{field}"), arg);
        out = out.replace(field.as_str(), arg);
    }
    out
}

fn build_inner_class_stubs(
    outer_cf: &ClassFile,
    inners: &std::collections::BTreeMap<String, ClassFile>,
) -> String {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    emit_nested_class_stubs(outer_cf, inners, 0, &mut visited)
}

fn is_anonymous_binary_name(binary: &str) -> bool {
    binary
        .rsplit('$')
        .next()
        .is_some_and(|tail: &str| !tail.is_empty() && tail.bytes().all(|b: u8| b.is_ascii_digit()))
}

const INNER_STUB_MAX_DEPTH: u32 = 8;
const INNER_STUB_MAX_CLASSES: usize = 4_096;
const INNER_CLASS_SHARED_FLAGS: u16 = ACC_PUBLIC
    | ACC_FINAL
    | ACC_INTERFACE
    | ACC_ABSTRACT
    | ACC_SYNTHETIC
    | ACC_ANNOTATION
    | ACC_ENUM;
const REJECTED_INNER_CLASSES: &str = "    /* unresolved inner classes */\n";

fn append_inner_output(out: &mut String, text: &str, limit: usize) -> bool {
    let Some(new_len): Option<usize> = out.len().checked_add(text.len()) else {
        return false;
    };
    if new_len > limit || out.try_reserve(text.len()).is_err() {
        return false;
    }
    out.push_str(text);
    true
}

fn append_inner_line(out: &mut String, text: &str, limit: usize) -> bool {
    append_inner_output(out, text, limit) && append_inner_output(out, "\n", limit)
}

fn reindent_block(block: &str, limit: usize) -> Option<String> {
    let mut out: String = String::new();
    for line in block.lines() {
        if line.is_empty() {
            if !append_inner_output(&mut out, "\n", limit) {
                return None;
            }
        } else if !append_inner_output(&mut out, "    ", limit)
            || !append_inner_line(&mut out, line, limit)
        {
            return None;
        }
    }
    Some(out)
}

fn emit_nested_class_stubs(
    outer_cf: &ClassFile,
    inners: &std::collections::BTreeMap<String, ClassFile>,
    depth: u32,
    visited: &mut BTreeSet<String>,
) -> String {
    let entries: Vec<crate::attributes::InnerClassEntry> =
        match crate::attributes::parse_inner_classes(outer_cf) {
            crate::attributes::InnerClassesAttribute::Absent => return String::new(),
            crate::attributes::InnerClassesAttribute::Rejected => {
                return REJECTED_INNER_CLASSES.to_string();
            }
            crate::attributes::InnerClassesAttribute::Parsed(entries) => entries,
        };
    let Ok(this_binary): core::result::Result<&str, _> = outer_cf.this_class_name() else {
        return REJECTED_INNER_CLASSES.to_string();
    };
    if depth >= INNER_STUB_MAX_DEPTH {
        return if entries
            .iter()
            .any(|entry: &crate::attributes::InnerClassEntry| {
                entry.outer_binary.as_deref() == Some(this_binary)
            }) {
            REJECTED_INNER_CLASSES.to_string()
        } else {
            String::new()
        };
    }
    let mut out: String = String::new();
    for entry in entries {
        if entry.outer_binary.as_deref() != Some(this_binary) {
            continue;
        }
        let Some(simple_name): Option<String> = entry.simple_name else {
            continue;
        };
        let binary_name: String = entry.inner_binary;
        let flags: u16 = entry.flags;
        let inner_key: String = format!("{binary_name}.class");
        let Some(inner_cf): Option<&ClassFile> = inners.get(&inner_key) else {
            continue;
        };
        if !inner_cf
            .this_class_name()
            .is_ok_and(|name: &str| name == binary_name.as_str())
        {
            return REJECTED_INNER_CLASSES.to_string();
        }
        if flags & INNER_CLASS_SHARED_FLAGS != inner_cf.access_flags & INNER_CLASS_SHARED_FLAGS {
            return REJECTED_INNER_CLASSES.to_string();
        }
        if flags & ACC_SYNTHETIC != 0 {
            continue;
        }
        if !crate::name_disambig::is_java_type_identifier(&simple_name)
            || visited.len() >= INNER_STUB_MAX_CLASSES
            || !visited.insert(binary_name.clone())
        {
            return REJECTED_INNER_CLASSES.to_string();
        }
        let structure: crate::attributes::ClassStructure = crate::attributes::analyze(inner_cf);
        let generic_class: Option<crate::signature::RecoveredClassSignature> =
            crate::signature::recover_class(inner_cf);
        let mut annotation_renderer: crate::attributes::DeclarationAnnotationRenderer =
            crate::attributes::DeclarationAnnotationRenderer::new(inner_cf);
        let type_params: String = generic_class
            .as_ref()
            .map_or_else(String::new, |signature| signature.type_parameters.clone());
        let is_inner_interface: bool = flags & 0x0200 != 0;
        let is_inner_enum: bool = flags & 0x4000 != 0;
        let is_inner_record: bool = structure.is_record;
        let is_inner_annotation: bool = flags & 0x2000 != 0;
        let enum_constants_degraded: bool =
            is_inner_enum && !enum_constants_recoverable(inner_cf, &structure);
        let is_inner_abstract: bool = flags & 0x0400 != 0 && !is_inner_interface;
        let is_inner_final: bool = flags & 0x0010 != 0;
        let access: &str = if flags & 0x0001 != 0 {
            "public "
        } else if flags & 0x0002 != 0 {
            "private "
        } else if flags & 0x0004 != 0 {
            "protected "
        } else {
            ""
        };
        let static_kw: &str = if flags & 0x0008 != 0 { "static " } else { "" };
        let abstract_kw: &str = if is_inner_abstract && !is_inner_enum {
            "abstract "
        } else {
            ""
        };
        let final_kw: &str = if is_inner_final && !is_inner_enum {
            "final "
        } else {
            ""
        };
        let nameable_permits: Vec<String> = if structure.is_sealed && !is_inner_enum {
            structure
                .permitted_subclasses
                .iter()
                .filter(|s: &&String| !is_anonymous_binary_name(s))
                .map(|s: &String| descriptor::binary_to_source(s))
                .collect()
        } else {
            Vec::new()
        };
        let permits_supported: bool = structure.is_sealed
            && !is_inner_enum
            && nameable_permits.len() == structure.permitted_subclasses.len()
            && !nameable_permits.is_empty();
        let sealed_kw: &str = if permits_supported { "sealed " } else { "" };
        let kind: &str = if is_inner_annotation {
            "@interface"
        } else if is_inner_interface {
            "interface"
        } else if is_inner_enum {
            "enum"
        } else if is_inner_record {
            "record"
        } else {
            "class"
        };
        let record_params: String = if is_inner_record {
            let components: Vec<String> = structure
                .record_components
                .iter()
                .filter_map(|c| {
                    let field: &FieldInfo = inner_cf.fields.iter().find(|field: &&FieldInfo| {
                        inner_cf
                            .utf8_at(field.name_index)
                            .is_ok_and(|name: &str| name == c.name)
                    })?;
                    let ty: String =
                        crate::signature::recover_field(inner_cf, field, generic_class.as_ref())
                            .or_else(|| {
                                descriptor::parse_field(&c.descriptor).map(|t| t.render())
                            })?;
                    Some(format!("{ty} {}", c.name))
                })
                .collect();
            format!("({})", components.join(", "))
        } else {
            String::new()
        };
        let super_clause: String = if !is_inner_interface && !is_inner_enum && !is_inner_record {
            if let Ok(sup_idx_ok) = Ok::<u16, ()>(inner_cf.super_class)
                && sup_idx_ok != 0
                && let Ok(sup) = inner_cf.class_name(sup_idx_ok)
                && sup != "java/lang/Object"
                && sup != "java/lang/Record"
                && sup != "java/lang/Enum"
            {
                let rendered: String = generic_class.as_ref().map_or_else(
                    || descriptor::binary_to_source(sup),
                    |signature: &crate::signature::RecoveredClassSignature| {
                        signature.superclass.clone()
                    },
                );
                format!(" extends {rendered}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let iface_clause: String = if !is_inner_annotation && !inner_cf.interfaces.is_empty() {
            let names: Vec<String> = generic_class.as_ref().map_or_else(
                || {
                    inner_cf
                        .interfaces
                        .iter()
                        .filter_map(|&idx| {
                            inner_cf
                                .class_name(idx)
                                .ok()
                                .map(descriptor::binary_to_source)
                        })
                        .collect()
                },
                |signature: &crate::signature::RecoveredClassSignature| {
                    signature.interfaces.clone()
                },
            );
            if names.is_empty() {
                String::new()
            } else {
                let verb: &str = if is_inner_interface {
                    "extends"
                } else {
                    "implements"
                };
                format!(" {verb} {}", names.join(", "))
            }
        } else {
            String::new()
        };
        let permits_clause: String = if permits_supported {
            format!(" permits {}", nameable_permits.join(", "))
        } else {
            String::new()
        };
        let rendered_annotations: String =
            annotation_renderer.render(inner_cf, &inner_cf.attributes, "    ");
        if !append_inner_output(&mut out, &rendered_annotations, MAX_RENDER_BYTES) {
            return REJECTED_INNER_CLASSES.to_string();
        }
        let declaration: String = format!(
            "    {access}{static_kw}{abstract_kw}{final_kw}{sealed_kw}{kind} {simple_name}{type_params}{record_params}{super_clause}{iface_clause}{permits_clause} {{"
        );
        if !append_inner_line(&mut out, &declaration, MAX_RENDER_BYTES) {
            return REJECTED_INNER_CLASSES.to_string();
        }
        if is_inner_enum {
            let mut enum_names: BTreeSet<&str> = BTreeSet::new();
            let enum_fields: Vec<&FieldInfo> = inner_cf
                .fields
                .iter()
                .filter(|field: &&FieldInfo| field.access_flags & ACC_ENUM != 0)
                .collect();
            if enum_fields.is_empty() && !append_inner_line(&mut out, "        ;", MAX_RENDER_BYTES)
            {
                return REJECTED_INNER_CLASSES.to_string();
            }
            for (index, field) in enum_fields.iter().enumerate() {
                let Ok(name): core::result::Result<&str, _> = inner_cf.utf8_at(field.name_index)
                else {
                    return REJECTED_INNER_CLASSES.to_string();
                };
                if !crate::name_disambig::is_java_type_identifier(name) || !enum_names.insert(name)
                {
                    return REJECTED_INNER_CLASSES.to_string();
                }
                let annotations: String =
                    annotation_renderer.render(inner_cf, &field.attributes, "        ");
                if !append_inner_output(&mut out, &annotations, MAX_RENDER_BYTES) {
                    return REJECTED_INNER_CLASSES.to_string();
                }
                let separator: char = if index + 1 == enum_fields.len() {
                    ';'
                } else {
                    ','
                };
                let declaration: String = format!("        {name}{separator}");
                if !append_inner_line(&mut out, &declaration, MAX_RENDER_BYTES) {
                    return REJECTED_INNER_CLASSES.to_string();
                }
            }
            if enum_constants_degraded {
                let marker_name: String = enum_degradation_marker_name(inner_cf);
                let marker: String = format!("        private static final int {marker_name} = 0;");
                if !append_inner_line(&mut out, &marker, MAX_RENDER_BYTES) {
                    return REJECTED_INNER_CLASSES.to_string();
                }
            }
        }
        if !is_inner_record {
            for field in &inner_cf.fields {
                if let Some(decl) = render_inner_field_stub(
                    &mut annotation_renderer,
                    inner_cf,
                    field,
                    is_inner_enum,
                    generic_class.as_ref(),
                ) && !append_inner_line(&mut out, &decl, MAX_RENDER_BYTES)
                {
                    return REJECTED_INNER_CLASSES.to_string();
                }
            }
        }
        let record_component_names: BTreeSet<String> = if is_inner_record {
            structure
                .record_components
                .iter()
                .map(|c: &crate::attributes::RecordComponent| c.name.clone())
                .collect()
        } else {
            BTreeSet::new()
        };
        let super_call: Option<String> = super_ctor_call(inner_cf, inners);
        let annotation_defaults: BTreeMap<usize, String> = if is_inner_annotation {
            crate::attributes::render_annotation_defaults(inner_cf)
        } else {
            BTreeMap::new()
        };
        for (method_index, method) in inner_cf.methods.iter().enumerate() {
            if is_inner_record
                && record_method_is_implicit(inner_cf, method, &record_component_names)
            {
                continue;
            }
            if let Some(stub) = render_inner_method_stub(
                &mut annotation_renderer,
                inner_cf,
                method,
                &simple_name,
                super_call.as_deref(),
                annotation_defaults.get(&method_index).map(String::as_str),
                generic_class.as_ref(),
            ) && !append_inner_line(&mut out, &stub, MAX_RENDER_BYTES)
            {
                return REJECTED_INNER_CLASSES.to_string();
            }
        }
        let nested: String = emit_nested_class_stubs(inner_cf, inners, depth + 1, visited);
        if !nested.is_empty() {
            let Some(remaining): Option<usize> = MAX_RENDER_BYTES.checked_sub(out.len()) else {
                return REJECTED_INNER_CLASSES.to_string();
            };
            let Some(indented): Option<String> = reindent_block(&nested, remaining) else {
                return REJECTED_INNER_CLASSES.to_string();
            };
            if !append_inner_output(&mut out, &indented, MAX_RENDER_BYTES) {
                return REJECTED_INNER_CLASSES.to_string();
            }
        }
        if !append_inner_line(&mut out, "    }", MAX_RENDER_BYTES) {
            return REJECTED_INNER_CLASSES.to_string();
        }
    }
    out
}

fn record_method_is_implicit(
    inner_cf: &ClassFile,
    method: &MethodInfo,
    components: &BTreeSet<String>,
) -> bool {
    let Ok(name) = inner_cf.utf8_at(method.name_index) else {
        return false;
    };
    if matches!(name, "<init>" | "toString" | "hashCode" | "equals") {
        return true;
    }
    let Ok(desc) = inner_cf.utf8_at(method.descriptor_index) else {
        return false;
    };
    components.contains(name) && desc.starts_with("()")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::classfile::{Attribute, ConstantPoolEntry};

    fn cp_utf8(s: &str) -> ConstantPoolEntry {
        ConstantPoolEntry::Utf8(s.to_string())
    }

    fn code_info(
        code: &[u8],
        exceptions: &[(u16, u16, u16, u16)],
        nested_attribute_names: &[u16],
    ) -> Vec<u8> {
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code.len() as u32).to_be_bytes());
        info.extend_from_slice(code);
        info.extend_from_slice(&(exceptions.len() as u16).to_be_bytes());
        for (start, end, handler, catch_type) in exceptions {
            info.extend_from_slice(&start.to_be_bytes());
            info.extend_from_slice(&end.to_be_bytes());
            info.extend_from_slice(&handler.to_be_bytes());
            info.extend_from_slice(&catch_type.to_be_bytes());
        }
        info.extend_from_slice(&(nested_attribute_names.len() as u16).to_be_bytes());
        for name_index in nested_attribute_names {
            info.extend_from_slice(&name_index.to_be_bytes());
            info.extend_from_slice(&0u32.to_be_bytes());
        }
        info
    }

    fn lookup_switch_code(default: i32, keys: [i32; 2]) -> Vec<u8> {
        let mut code: Vec<u8> = vec![0xAB, 0x00, 0x00, 0x00];
        code.extend_from_slice(&default.to_be_bytes());
        code.extend_from_slice(&2i32.to_be_bytes());
        for key in keys {
            code.extend_from_slice(&key.to_be_bytes());
            code.extend_from_slice(&28i32.to_be_bytes());
        }
        code.push(0xB1);
        code
    }

    fn class_with_method_code(code_info: Option<Vec<u8>>, access_flags: u16) -> ClassFile {
        let constant_pool: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            cp_utf8("DecodeStates"),
            ConstantPoolEntry::Class { name_index: 1 },
            cp_utf8("java/lang/Object"),
            ConstantPoolEntry::Class { name_index: 3 },
            cp_utf8("body"),
            cp_utf8("()V"),
            cp_utf8("Code"),
        ];
        let attributes: Vec<Attribute> = code_info.map_or_else(Vec::new, |info: Vec<u8>| {
            vec![Attribute {
                name_index: 7,
                info,
            }]
        });
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool,
            access_flags: ACC_PUBLIC | (access_flags & ACC_ABSTRACT),
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags,
                name_index: 5,
                descriptor_index: 6,
                attributes,
            }],
            attributes: Vec::new(),
        }
    }

    #[test]
    fn malformed_code_attribute_is_reported_as_fallback() {
        let malformed_info: Vec<u8> = vec![0; 7];
        assert!(parse_code_attribute(&malformed_info).is_err());
        let class: ClassFile =
            class_with_method_code(Some(malformed_info), ACC_PUBLIC | ACC_STATIC);
        assert!(matches!(
            find_code(&class, &class.methods[0]),
            MethodCode::Refused(_)
        ));
        let decompiled: DecompiledClass = decompile_class(&class);
        assert_eq!(decompiled.method_count, 1);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn invalid_class_metadata_refuses_every_method() {
        let mut class: ClassFile =
            class_with_method_code(Some(code_info(&[0xB1], &[], &[])), ACC_PUBLIC | ACC_STATIC);
        class.this_class = 1;

        let decompiled: DecompiledClass = decompile_class(&class);
        assert_eq!(decompiled.method_count, 1);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn malformed_code_on_abstract_method_is_reported_as_fallback() {
        let malformed_info: Vec<u8> = vec![0; 7];
        assert!(parse_code_attribute(&malformed_info).is_err());
        let class: ClassFile =
            class_with_method_code(Some(malformed_info), ACC_PUBLIC | ACC_ABSTRACT);
        let decompiled: DecompiledClass = decompile_class(&class);

        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn absent_decoded_noop_and_zero_length_code_are_distinct() {
        let absent: DecompiledClass =
            decompile_class(&class_with_method_code(None, ACC_PUBLIC | ACC_ABSTRACT));
        let noop: DecompiledClass = decompile_class(&class_with_method_code(
            Some(code_info(&[0xB1], &[], &[])),
            ACC_PUBLIC | ACC_STATIC,
        ));
        let zero_length_info: Vec<u8> = vec![0; 12];
        assert!(parse_code_attribute(&zero_length_info).is_err());
        let zero_length: DecompiledClass = decompile_class(&class_with_method_code(
            Some(zero_length_info),
            ACC_PUBLIC | ACC_STATIC,
        ));

        assert_eq!(absent.fully_lifted_methods, 0);
        assert_eq!(absent.fallback_methods, 0);
        assert!(absent.source.contains("public abstract void body();"));
        assert_eq!(noop.fully_lifted_methods, 1);
        assert_eq!(noop.fallback_methods, 0);
        assert!(noop.source.contains("public static void body() {"));
        assert_eq!(zero_length.fully_lifted_methods, 0);
        assert_eq!(zero_length.fallback_methods, 1);
        assert!(
            zero_length
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn malformed_field_metadata_is_reported_in_source() {
        let constant_pool: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            cp_utf8("MalformedField"),
            ConstantPoolEntry::Class { name_index: 1 },
            cp_utf8("java/lang/Object"),
            ConstantPoolEntry::Class { name_index: 3 },
            cp_utf8("field"),
            cp_utf8("I"),
        ];
        let mut class: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: vec![FieldInfo {
                access_flags: ACC_PUBLIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: Vec::new(),
            }],
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        class.fields[0].descriptor_index = 5;

        let decompiled: DecompiledClass = decompile_class(&class);
        assert_eq!(decompiled.field_count, 1);
        assert_eq!(decompiled.decode_error_count, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed field metadata>")
        );
    }

    #[test]
    fn concrete_method_without_code_is_reported_as_fallback() {
        let decompiled: DecompiledClass =
            decompile_class(&class_with_method_code(None, ACC_PUBLIC | ACC_STATIC));
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
        assert!(
            decompiled
                .source
                .contains("throw new UnsupportedOperationException(\"malformed bytecode\");")
        );
    }

    #[test]
    fn concrete_interface_method_without_code_is_reported_as_fallback() {
        let mut class: ClassFile = class_with_method_code(None, ACC_PUBLIC);
        class.access_flags = ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT;
        let decompiled: DecompiledClass = decompile_class(&class);

        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(decompiled.source.contains("public default void body() {"));
        assert!(
            decompiled
                .source
                .contains("throw new UnsupportedOperationException(\"malformed bytecode\");")
        );
    }

    #[test]
    fn invalid_attribute_name_before_code_is_reported_as_fallback() {
        let mut class: ClassFile =
            class_with_method_code(Some(code_info(&[0xB1], &[], &[])), ACC_PUBLIC | ACC_STATIC);
        class.methods[0].attributes.insert(
            0,
            Attribute {
                name_index: u16::MAX,
                info: Vec::new(),
            },
        );
        let decompiled: DecompiledClass = decompile_class(&class);

        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn duplicate_code_attributes_are_reported_as_fallback() {
        let mut class: ClassFile =
            class_with_method_code(Some(code_info(&[0xB1], &[], &[])), ACC_PUBLIC | ACC_STATIC);
        let duplicate: Attribute = Attribute {
            name_index: 7,
            info: code_info(&[0xB1], &[], &[]),
        };
        class.methods[0].attributes.push(duplicate);
        let decompiled: DecompiledClass = decompile_class(&class);

        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn invalid_code_semantics_are_reported_as_fallback() {
        let cases: [Vec<u8>; 10] = [
            code_info(&[0x10, 0x01, 0xB1], &[(1, 2, 2, 0)], &[]),
            code_info(&[0xB1], &[(0, 1, 0, 1)], &[]),
            code_info(&[0xB1], &[], &[u16::MAX]),
            code_info(&[0xCA], &[], &[]),
            code_info(&[0xC4, 0xB1, 0x00, 0x00], &[], &[]),
            code_info(&[0xA7, 0x00, 0x01, 0xB1], &[], &[]),
            code_info(&lookup_switch_code(28, [2, 1]), &[], &[]),
            code_info(&lookup_switch_code(1, [1, 2]), &[], &[]),
            code_info(&[0x12, 0xFF, 0xB0], &[], &[]),
            code_info(&[0xB8, 0x00, 0x01, 0xB1], &[], &[]),
        ];
        for info in cases {
            let class: ClassFile = class_with_method_code(Some(info), ACC_PUBLIC | ACC_STATIC);
            let decompiled: DecompiledClass = decompile_class(&class);
            assert_eq!(decompiled.fully_lifted_methods, 0);
            assert_eq!(decompiled.fallback_methods, 1);
            assert!(
                decompiled
                    .source
                    .contains("<decompile: malformed bytecode>")
            );
        }
    }

    #[test]
    fn missing_bootstrap_method_is_reported_as_fallback() {
        let mut class: ClassFile = class_with_method_code(
            Some(code_info(&[0xBA, 0x00, 0x0A, 0x00, 0x00, 0xB1], &[], &[])),
            ACC_PUBLIC | ACC_STATIC,
        );
        class.constant_pool.push(cp_utf8("dynamicCall"));
        class.constant_pool.push(ConstantPoolEntry::NameAndType {
            name_index: 8,
            descriptor_index: 6,
        });
        class.constant_pool.push(ConstantPoolEntry::InvokeDynamic {
            bootstrap_method_attr_index: 0,
            name_and_type_index: 9,
        });

        let decompiled: DecompiledClass = decompile_class(&class);
        assert_eq!(decompiled.fully_lifted_methods, 0);
        assert_eq!(decompiled.fallback_methods, 1);
        assert_eq!(decompiled.decode_error_count, 1);
        assert!(
            decompiled
                .source
                .contains("<decompile: malformed bytecode>")
        );
    }

    #[test]
    fn invalid_method_metadata_is_reported_as_fallback() {
        let mut invalid_name: ClassFile =
            class_with_method_code(Some(code_info(&[0xB1], &[], &[])), ACC_PUBLIC | ACC_STATIC);
        invalid_name.methods[0].name_index = u16::MAX;
        let mut invalid_descriptor: ClassFile =
            class_with_method_code(Some(code_info(&[0xB1], &[], &[])), ACC_PUBLIC | ACC_STATIC);
        invalid_descriptor.methods[0].descriptor_index = 5;
        for class in [invalid_name, invalid_descriptor] {
            let decompiled: DecompiledClass = decompile_class(&class);
            assert_eq!(decompiled.fully_lifted_methods, 0);
            assert_eq!(decompiled.fallback_methods, 1);
            assert!(
                decompiled
                    .source
                    .contains("<decompile: malformed bytecode>")
            );
        }
    }

    #[test]
    fn generic_cast_rewrite_skips_literals_and_comments() {
        let source: &str = "x = ((Object) var1); s = \"((Object) var1)\"; // ((Object) var1)\ny = ((Object) var1);";
        assert_eq!(
            replace_java_code(source, "((Object) var1)", "((T) var1)"),
            "x = ((T) var1); s = \"((Object) var1)\"; // ((Object) var1)\ny = ((T) var1);"
        );
    }

    #[test]
    fn generic_cast_rewrite_uses_longest_match_in_one_pass() {
        let replacements: BTreeMap<String, String> = BTreeMap::from([
            ("((Object)".to_string(), "((T)".to_string()),
            ("((Object) var1)".to_string(), "((R) var1)".to_string()),
        ]);
        let replaced: Option<String> = replace_java_code_many(
            "a = ((Object) var1); b = ((Object) var2); \"((Object) var1)\";",
            &replacements,
        );
        assert_eq!(
            replaced.as_deref(),
            Some("a = ((R) var1); b = ((T) var2); \"((Object) var1)\";")
        );
    }

    #[test]
    fn generic_cast_rewrite_rejects_expanded_output_over_limit() {
        let source: String = "x".repeat(MAX_RENDER_BYTES / 2 + 1);
        let replacements: BTreeMap<String, String> =
            BTreeMap::from([("x".to_string(), "xx".to_string())]);
        assert!(replace_java_code_many(&source, &replacements).is_none());
    }

    #[test]
    fn class_type_variable_return_is_adapted_and_checked() {
        let recovered: crate::signature::RecoveredMethodSignature =
            crate::signature::RecoveredMethodSignature {
                type_parameters: String::new(),
                parameters: Vec::new(),
                result: "T".to_string(),
                throws: Vec::new(),
                type_parameter_names: BTreeSet::from(["T".to_string()]),
                type_parameter_erasures: BTreeMap::from([("T".to_string(), "Object".to_string())]),
            };
        let adapted: Option<String> = adapt_generic_body("        return \"value\";\n", &recovered);
        assert!(
            adapted
                .as_ref()
                .is_some_and(|source: &String| source.contains("return ((T) (\"value\"));"))
        );
        assert!(
            adapted.as_ref().is_some_and(|source: &String| {
                generic_body_source_compatible(source, &recovered)
            })
        );
    }

    fn c(s: &str) -> Expr {
        Expr::Const(s.to_string())
    }

    fn folded_text(op: &str, kind: NumKind, lhs: &str, rhs: &str) -> Option<String> {
        folded_binary(op, kind, &c(lhs), &c(rhs)).map(|e: Expr| e.render())
    }

    #[test]
    fn long_xor_chain_folds_to_single_literal() {
        assert_eq!(
            folded_text(
                "^",
                NumKind::Long,
                "1234605616436508552L",
                "1085102592571150095L"
            )
            .as_deref(),
            Some("2174460489426892935L")
        );
    }

    #[test]
    fn int_add_wraps_at_32_bits() {
        assert_eq!(
            folded_text("+", NumKind::Int, "2147483647", "1").as_deref(),
            Some("-2147483648")
        );
    }

    #[test]
    fn long_left_shift_uses_int_count_and_masks_to_six_bits() {
        assert_eq!(
            folded_text("<<", NumKind::Long, "1L", "65").as_deref(),
            Some("2L")
        );
    }

    #[test]
    fn division_by_zero_is_not_folded() {
        assert!(folded_text("/", NumKind::Int, "10", "0").is_none());
        assert!(folded_text("%", NumKind::Long, "10L", "0L").is_none());
    }

    #[test]
    fn float_and_double_arithmetic_is_left_untouched() {
        assert!(folded_text("+", NumKind::Other, "1.5f", "2.5f").is_none());
        assert!(folded_text("*", NumKind::Other, "2.0", "3.0").is_none());
    }

    #[test]
    fn non_literal_operands_are_left_as_an_expression() {
        assert!(folded_binary("+", NumKind::Int, &Expr::Local("x".to_string()), &c("1")).is_none());
    }

    #[test]
    fn long_negate_folds_with_suffix() {
        assert_eq!(
            folded_unary(NumKind::Long, &c("5L"))
                .map(|e: Expr| e.render())
                .as_deref(),
            Some("-5L")
        );
    }

    #[test]
    fn arith_and_shift_kind_mapping_matches_jvm_opcodes() {
        assert_eq!(arith_num_kind(0x60), NumKind::Int);
        assert_eq!(arith_num_kind(0x61), NumKind::Long);
        assert_eq!(arith_num_kind(0x62), NumKind::Other);
        assert_eq!(shift_num_kind(0x78), NumKind::Int);
        assert_eq!(shift_num_kind(0x79), NumKind::Long);
        assert_eq!(shift_num_kind(0x7E), NumKind::Int);
        assert_eq!(shift_num_kind(0x7F), NumKind::Long);
        assert_eq!(shift_num_kind(0x83), NumKind::Long);
    }

    #[test]
    fn access_keywords_render() {
        assert_eq!(
            member_access_keywords(ACC_PUBLIC | ACC_STATIC),
            "public static"
        );
        assert_eq!(
            member_access_keywords(ACC_PRIVATE | ACC_FINAL),
            "private final"
        );
    }

    #[test]
    fn decompiles_minimal_class_header() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("package com.example;"));
        assert!(d.source.contains("public class Foo {"));
    }

    #[test]
    fn constant_value_initializer_requires_descriptor_compatible_pool_entry() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            cp_utf8("ConstantValue"),
            ConstantPoolEntry::Integer(1),
            ConstantPoolEntry::Long(1),
            ConstantPoolEntry::Integer(65_536),
        ];
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 61,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let field_with: fn(u16) -> FieldInfo = |index: u16| FieldInfo {
            access_flags: ACC_STATIC | ACC_FINAL,
            name_index: 0,
            descriptor_index: 0,
            attributes: vec![Attribute {
                name_index: 1,
                info: index.to_be_bytes().to_vec(),
            }],
        };
        assert_eq!(
            constant_value_initializer(&cf, &field_with(2), &JavaType::Boolean).as_deref(),
            Some("true")
        );
        assert!(constant_value_initializer(&cf, &field_with(3), &JavaType::Int).is_none());
        assert!(constant_value_initializer(&cf, &field_with(4), &JavaType::Char).is_none());
        let mut instance: FieldInfo = field_with(2);
        instance.access_flags &= !ACC_STATIC;
        assert!(constant_value_initializer(&cf, &instance, &JavaType::Int).is_none());
        let mut duplicate: FieldInfo = field_with(2);
        duplicate.attributes.push(Attribute {
            name_index: 1,
            info: 2u16.to_be_bytes().to_vec(),
        });
        assert!(constant_value_initializer(&cf, &duplicate, &JavaType::Int).is_none());
    }

    #[test]
    fn static_initializer_annotations_emit_source_rejection_marker() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            cp_utf8("MarkedStatic"),
            ConstantPoolEntry::Class { name_index: 1 },
            cp_utf8("java/lang/Object"),
            ConstantPoolEntry::Class { name_index: 3 },
            cp_utf8("<clinit>"),
            cp_utf8("()V"),
            cp_utf8("Code"),
            cp_utf8("RuntimeVisibleAnnotations"),
            cp_utf8("LMark;"),
        ];
        let code_info: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 1, 0xB1, 0, 0, 0, 0];
        let annotation_info: Vec<u8> = vec![0, 1, 0, 9, 0, 0];
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 61,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![
                    Attribute {
                        name_index: 7,
                        info: code_info,
                    },
                    Attribute {
                        name_index: 8,
                        info: annotation_info,
                    },
                ],
            }],
            attributes: Vec::new(),
        };
        let source: String = decompile_class(&cf).source;
        assert!(source.contains("/* unresolved static initializer annotations */"));
        assert!(!source.contains("@Mark\n    static"));
    }

    #[test]
    fn lifts_iconst_ireturn_method() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("answer"));
        cp.push(cp_utf8("()I"));
        cp.push(cp_utf8("Code"));
        let code_body: Vec<u8> = vec![0x05, 0xAC];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![Attribute {
                    name_index: 7,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(
            d.source.contains("public static int answer()"),
            "{}",
            d.source
        );
        assert!(d.source.contains("return 2"), "{}", d.source);
        assert_eq!(d.fully_lifted_methods, 1);
    }

    #[test]
    fn dup_bomb_method_stays_bounded() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("bomb"));
        cp.push(cp_utf8("(I)I"));
        cp.push(cp_utf8("Code"));
        let mut code_body: Vec<u8> = vec![0x1A];
        for _ in 0..60 {
            code_body.push(0x59);
            code_body.push(0x68);
        }
        code_body.push(0xAC);
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![Attribute {
                    name_index: 7,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(
            d.source.len() < 1_000_000,
            "dup-bomb output must stay bounded, got {} bytes",
            d.source.len()
        );
        assert!(
            d.source.contains(HOLE_RENDER),
            "dup-bomb cap must emit opaque hole marker"
        );
    }

    #[test]
    fn constant_dup_bomb_is_defused_by_folding() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("bomb"));
        cp.push(cp_utf8("()I"));
        cp.push(cp_utf8("Code"));
        let mut code_body: Vec<u8> = vec![0x05];
        for _ in 0..60 {
            code_body.push(0x59);
            code_body.push(0x68);
        }
        code_body.push(0xAC);
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&4u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&(code_body.len() as u32).to_be_bytes());
        info.extend_from_slice(&code_body);
        info.extend_from_slice(&0u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_STATIC,
                name_index: 5,
                descriptor_index: 6,
                attributes: vec![Attribute {
                    name_index: 7,
                    info,
                }],
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(
            d.source.contains("return 0;"),
            "a constant 2*2*... square chain folds (i32-wrapping) to a single return 0; got:\n{}",
            d.source
        );
        assert!(
            !d.source.contains(HOLE_RENDER) && !d.source.contains(" * "),
            "the folded chain leaves no residual multiply nor a hole marker; got:\n{}",
            d.source
        );
    }

    #[test]
    fn lifts_field_and_static_field_access() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Foo"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("count"));
        cp.push(cp_utf8("I"));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: vec![FieldInfo {
                access_flags: ACC_PRIVATE,
                name_index: 5,
                descriptor_index: 6,
                attributes: Vec::new(),
            }],
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("private int count;"), "{}", d.source);
    }

    #[test]
    fn interface_method_renders_abstract() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(cp_utf8("com/example/Service"));
        cp.push(ConstantPoolEntry::Class { name_index: 1 });
        cp.push(cp_utf8("java/lang/Object"));
        cp.push(ConstantPoolEntry::Class { name_index: 3 });
        cp.push(cp_utf8("run"));
        cp.push(cp_utf8("()V"));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT,
            this_class: 2,
            super_class: 4,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: vec![MethodInfo {
                access_flags: ACC_PUBLIC | ACC_ABSTRACT,
                name_index: 5,
                descriptor_index: 6,
                attributes: Vec::new(),
            }],
            attributes: Vec::new(),
        };
        let d: DecompiledClass = decompile_class(&cf);
        assert!(d.source.contains("interface Service"), "{}", d.source);
        assert!(d.source.contains("void run();"), "{}", d.source);
    }
}
