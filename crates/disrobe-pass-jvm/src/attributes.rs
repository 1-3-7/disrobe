use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::bytecode::escape_java_string;
use crate::classfile::{Attribute, ClassFile, ConstantPoolEntry, MethodInfo};
use crate::descriptor::{self, JavaType};

const MAX_ANNOTATION_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ANNOTATION_NODES: usize = 65_535;
const MAX_ANNOTATION_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ANNOTATION_DEPTH: usize = 64;
const MAX_ANNOTATION_RENDER_BYTES: usize = 4 * 1024 * 1024;
const UNRESOLVED_ANNOTATION: &str = "@<unresolved-annotation>";
const UNRESOLVED_ANNOTATION_VALUE: &str = "<unresolved-annotation-value>";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnnotationError(&'static str);

impl std::fmt::Display for AnnotationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "DR-JVM-0034: malformed declaration annotation attribute: {}",
            self.0
        )
    }
}

type AnnotationResult<T> = core::result::Result<T, AnnotationError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnnotationElement {
    pub(crate) name: String,
    pub(crate) value: AnnotationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Annotation {
    pub(crate) type_descriptor: String,
    pub(crate) elements: Vec<AnnotationElement>,
}

impl Annotation {
    #[must_use]
    pub(crate) fn element(&self, name: &str) -> Option<&AnnotationValue> {
        self.elements
            .iter()
            .find(|element: &&AnnotationElement| element.name == name)
            .map(|element: &AnnotationElement| &element.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnnotationValue {
    Byte(i8),
    Char(u16),
    Double(u64),
    Float(u32),
    Int(i32),
    Long(i64),
    Short(i16),
    Boolean(bool),
    String(String),
    Enum {
        type_descriptor: String,
        constant_name: String,
    },
    Class(String),
    Annotation(Box<Annotation>),
    Array(Vec<Self>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum AnnotationOutcome {
    #[default]
    Absent,
    Parsed(Vec<Annotation>),
    Rejected {
        instances: usize,
        reasons: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DeclarationAnnotations {
    pub(crate) visible: AnnotationOutcome,
    pub(crate) invisible: AnnotationOutcome,
}

struct AnnotationParseBudget {
    input_bytes: usize,
    nodes: usize,
    text_bytes: usize,
}

impl AnnotationParseBudget {
    const fn new() -> Self {
        Self {
            input_bytes: MAX_ANNOTATION_INPUT_BYTES,
            nodes: MAX_ANNOTATION_NODES,
            text_bytes: MAX_ANNOTATION_TEXT_BYTES,
        }
    }

    fn charge_input(&mut self, amount: usize) -> AnnotationResult<()> {
        self.input_bytes = self
            .input_bytes
            .checked_sub(amount)
            .ok_or(AnnotationError("annotation input quota exceeded"))?;
        Ok(())
    }

    fn charge_node(&mut self) -> AnnotationResult<()> {
        self.nodes = self
            .nodes
            .checked_sub(1)
            .ok_or(AnnotationError("annotation node quota exceeded"))?;
        Ok(())
    }

    fn charge_text(&mut self, amount: usize) -> AnnotationResult<()> {
        self.text_bytes = self
            .text_bytes
            .checked_sub(amount)
            .ok_or(AnnotationError("annotation text quota exceeded"))?;
        Ok(())
    }
}

struct AnnotationRenderBudget {
    bytes_remaining: usize,
}

impl AnnotationRenderBudget {
    const fn new() -> Self {
        Self {
            bytes_remaining: MAX_ANNOTATION_RENDER_BYTES,
        }
    }

    fn push(&mut self, out: &mut String, text: &str) -> Option<()> {
        self.bytes_remaining = self.bytes_remaining.checked_sub(text.len())?;
        out.try_reserve(text.len()).ok()?;
        out.push_str(text);
        Some(())
    }

    fn push_char(&mut self, out: &mut String, value: char) -> Option<()> {
        self.bytes_remaining = self.bytes_remaining.checked_sub(value.len_utf8())?;
        out.try_reserve(value.len_utf8()).ok()?;
        out.push(value);
        Some(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InnerClassEntry {
    pub(crate) flags: u16,
    pub(crate) inner_binary: String,
    pub(crate) outer_binary: Option<String>,
    pub(crate) simple_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InnerClassesAttribute {
    Absent,
    Parsed(Vec<InnerClassEntry>),
    Rejected,
}

#[must_use]
pub(crate) fn parse_inner_classes(cf: &ClassFile) -> InnerClassesAttribute {
    let mut found: Option<&Attribute> = None;
    for attr in &cf.attributes {
        if !cf
            .utf8_at(attr.name_index)
            .is_ok_and(|name: &str| name == "InnerClasses")
        {
            continue;
        }
        if found.is_some() {
            return InnerClassesAttribute::Rejected;
        }
        found = Some(attr);
    }
    let Some(attr): Option<&Attribute> = found else {
        return InnerClassesAttribute::Absent;
    };
    let mut reader: ByteReader<'_> = ByteReader::new(&attr.info);
    let Some(count): Option<u16> = reader.read_u16_be().ok() else {
        return InnerClassesAttribute::Rejected;
    };
    let Some(expected_bytes): Option<usize> = usize::from(count).checked_mul(8) else {
        return InnerClassesAttribute::Rejected;
    };
    if reader.remaining() != expected_bytes {
        return InnerClassesAttribute::Rejected;
    }
    let mut entries: Vec<InnerClassEntry> = Vec::new();
    if entries.try_reserve(usize::from(count)).is_err() {
        return InnerClassesAttribute::Rejected;
    }
    let mut seen_binaries: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_indices: BTreeSet<u16> = BTreeSet::new();
    let mut text_bytes_remaining: usize = MAX_ANNOTATION_TEXT_BYTES;
    for _ in 0..count {
        let Some(inner_index): Option<u16> = reader.read_u16_be().ok() else {
            return InnerClassesAttribute::Rejected;
        };
        let Some(outer_index): Option<u16> = reader.read_u16_be().ok() else {
            return InnerClassesAttribute::Rejected;
        };
        let Some(name_index): Option<u16> = reader.read_u16_be().ok() else {
            return InnerClassesAttribute::Rejected;
        };
        let Some(flags): Option<u16> = reader.read_u16_be().ok() else {
            return InnerClassesAttribute::Rejected;
        };
        if inner_index == 0
            || inner_index == outer_index
            || !seen_indices.insert(inner_index)
            || cf.major_version >= 51 && name_index == 0 && outer_index != 0
        {
            return InnerClassesAttribute::Rejected;
        }
        let Some(inner): Option<&str> = cf.class_name(inner_index).ok() else {
            return InnerClassesAttribute::Rejected;
        };
        let outer: Option<&str> = if outer_index == 0 {
            None
        } else {
            let Some(outer): Option<&str> = cf.class_name(outer_index).ok() else {
                return InnerClassesAttribute::Rejected;
            };
            Some(outer)
        };
        let simple: Option<&str> = if name_index == 0 {
            None
        } else {
            let Some(simple): Option<&str> = cf.utf8_at(name_index).ok() else {
                return InnerClassesAttribute::Rejected;
            };
            Some(simple)
        };
        if let (Some(outer), Some(simple)) = (outer, simple) {
            let relation_name: Option<&str> = inner
                .strip_prefix(outer)
                .and_then(|suffix: &str| suffix.strip_prefix('$'));
            if relation_name != Some(simple) {
                return InnerClassesAttribute::Rejected;
            }
        }
        let Some(text_bytes): Option<usize> = inner
            .len()
            .checked_add(outer.map_or(0, str::len))
            .and_then(|size: usize| size.checked_add(simple.map_or(0, str::len)))
        else {
            return InnerClassesAttribute::Rejected;
        };
        let Some(remaining): Option<usize> = text_bytes_remaining.checked_sub(text_bytes) else {
            return InnerClassesAttribute::Rejected;
        };
        text_bytes_remaining = remaining;
        let entry: InnerClassEntry = InnerClassEntry {
            flags,
            inner_binary: inner.to_string(),
            outer_binary: outer.map(str::to_string),
            simple_name: simple.map(str::to_string),
        };
        if let Some(existing_index) = seen_binaries.get(inner).copied() {
            if entries.get(existing_index) != Some(&entry) {
                return InnerClassesAttribute::Rejected;
            }
            continue;
        }
        seen_binaries.insert(entry.inner_binary.clone(), entries.len());
        entries.push(entry);
    }
    if reader.remaining() != 0 {
        return InnerClassesAttribute::Rejected;
    }
    InnerClassesAttribute::Parsed(entries)
}

struct AnnotationNameResolver {
    inner_classes: BTreeMap<String, (String, String)>,
    resolution_bytes: Cell<usize>,
    resolution_steps: Cell<usize>,
    usable: bool,
}

impl AnnotationNameResolver {
    fn new(cf: &ClassFile) -> Self {
        let mut inner_classes: BTreeMap<String, (String, String)> = BTreeMap::new();
        let usable: bool = match parse_inner_classes(cf) {
            InnerClassesAttribute::Absent => true,
            InnerClassesAttribute::Rejected => false,
            InnerClassesAttribute::Parsed(entries) => {
                for entry in entries {
                    if let (Some(outer), Some(simple)) = (entry.outer_binary, entry.simple_name) {
                        inner_classes.insert(entry.inner_binary, (outer, simple));
                    }
                }
                true
            }
        };
        Self {
            inner_classes,
            resolution_bytes: Cell::new(MAX_ANNOTATION_TEXT_BYTES),
            resolution_steps: Cell::new(MAX_ANNOTATION_NODES),
            usable,
        }
    }

    fn source_name(&self, internal: &str, depth: usize) -> Option<String> {
        if !self.usable || depth >= MAX_ANNOTATION_DEPTH {
            return None;
        }
        let remaining_steps: usize = self.resolution_steps.get().checked_sub(1)?;
        let remaining_bytes: usize = self.resolution_bytes.get().checked_sub(internal.len())?;
        self.resolution_steps.set(remaining_steps);
        self.resolution_bytes.set(remaining_bytes);
        let rewritten_internal: String = crate::name_disambig::rewrite_active(internal);
        if let Some((outer, simple)) = self.inner_classes.get(internal) {
            if !crate::name_disambig::is_java_type_identifier(simple) {
                return None;
            }
            let mut source: String = self.source_name(outer, depth + 1)?;
            source.push('.');
            source.push_str(simple);
            return Some(source);
        }
        valid_source_internal_name(&rewritten_internal)
            .then(|| rewritten_internal.replace('/', "."))
    }
}

fn object_internal_name(descriptor_text: &str) -> Option<&str> {
    let JavaType::Object(_) = descriptor::parse_field(descriptor_text)? else {
        return None;
    };
    descriptor_text.strip_prefix('L')?.strip_suffix(';')
}

fn valid_jvm_unqualified_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|ch: char| matches!(ch, '.' | ';' | '[' | '/'))
}

fn valid_jvm_internal_name(internal: &str) -> bool {
    !internal.is_empty() && internal.split('/').all(valid_jvm_unqualified_name)
}

fn valid_jvm_method_name(name: &str) -> bool {
    valid_jvm_unqualified_name(name) && !name.chars().any(|ch: char| matches!(ch, '<' | '>'))
}

fn valid_source_internal_name(internal: &str) -> bool {
    let (package, leaf): (&str, &str) = match internal.rsplit_once('/') {
        Some((package, leaf)) => (package, leaf),
        None => ("", internal),
    };
    crate::name_disambig::is_java_type_identifier(leaf)
        && (package.is_empty()
            || package
                .split('/')
                .all(crate::name_disambig::is_java_source_identifier))
}

fn valid_jvm_object_descriptor(descriptor_text: &str) -> bool {
    object_internal_name(descriptor_text).is_some_and(valid_jvm_internal_name)
}

fn valid_jvm_class_type(ty: &JavaType) -> bool {
    match ty {
        JavaType::Object(descriptor_text) => valid_jvm_object_descriptor(descriptor_text),
        JavaType::Array(inner) => {
            !matches!(inner.as_ref(), JavaType::Void) && valid_jvm_class_type(inner)
        }
        _ => true,
    }
}

fn valid_jvm_class_descriptor(descriptor_text: &str) -> bool {
    descriptor::parse_field(descriptor_text).is_some_and(|ty: JavaType| valid_jvm_class_type(&ty))
}

fn object_descriptor_source(
    resolver: &AnnotationNameResolver,
    descriptor_text: &str,
) -> Option<String> {
    resolver.source_name(object_internal_name(descriptor_text)?, 0)
}

fn class_type_source(resolver: &AnnotationNameResolver, ty: &JavaType) -> Option<String> {
    match ty {
        JavaType::Object(descriptor_text) => {
            resolver.source_name(object_internal_name(descriptor_text)?, 0)
        }
        JavaType::Array(inner) if !matches!(inner.as_ref(), JavaType::Void) => {
            Some(format!("{}[]", class_type_source(resolver, inner)?))
        }
        JavaType::Array(_) => None,
        _ => Some(ty.render()),
    }
}

fn class_descriptor_source(
    resolver: &AnnotationNameResolver,
    descriptor_text: &str,
) -> Option<String> {
    class_type_source(resolver, &descriptor::parse_field(descriptor_text)?)
}

fn float_literal(bits: u32) -> Option<String> {
    let value: f32 = f32::from_bits(bits);
    if value.is_nan() {
        (bits == f32::NAN.to_bits()).then(|| "(0.0f / 0.0f)".to_string())
    } else if value == f32::INFINITY {
        Some("(1.0f / 0.0f)".to_string())
    } else if value == f32::NEG_INFINITY {
        Some("(-1.0f / 0.0f)".to_string())
    } else {
        Some(format!("{value:?}f"))
    }
}

fn double_literal(bits: u64) -> Option<String> {
    let value: f64 = f64::from_bits(bits);
    if value.is_nan() {
        (bits == f64::NAN.to_bits()).then(|| "(0.0 / 0.0)".to_string())
    } else if value == f64::INFINITY {
        Some("(1.0 / 0.0)".to_string())
    } else if value == f64::NEG_INFINITY {
        Some("(-1.0 / 0.0)".to_string())
    } else {
        Some(format!("{value:?}"))
    }
}

fn render_value(
    value: &AnnotationValue,
    resolver: &AnnotationNameResolver,
    depth: usize,
    out: &mut String,
    budget: &mut AnnotationRenderBudget,
) -> Option<()> {
    if depth >= MAX_ANNOTATION_DEPTH {
        return None;
    }
    match value {
        AnnotationValue::Byte(value) => budget.push(out, &format!("(byte) {value}")),
        AnnotationValue::Char(value) => budget.push(out, &format!("(char) {value}")),
        AnnotationValue::Double(bits) => budget.push(out, &double_literal(*bits)?),
        AnnotationValue::Float(bits) => budget.push(out, &float_literal(*bits)?),
        AnnotationValue::Int(value) => budget.push(out, &value.to_string()),
        AnnotationValue::Long(value) => budget.push(out, &format!("{value}L")),
        AnnotationValue::Short(value) => budget.push(out, &format!("(short) {value}")),
        AnnotationValue::Boolean(value) => budget.push(out, if *value { "true" } else { "false" }),
        AnnotationValue::String(value) => budget.push(out, &escape_java_string(value)),
        AnnotationValue::Enum {
            type_descriptor,
            constant_name,
        } => {
            if !crate::name_disambig::is_java_source_identifier(constant_name) {
                return None;
            }
            let owner: String = object_descriptor_source(resolver, type_descriptor)?;
            budget.push(out, &owner)?;
            budget.push_char(out, '.')?;
            budget.push(out, constant_name)
        }
        AnnotationValue::Class(type_descriptor) => {
            let ty: String = class_descriptor_source(resolver, type_descriptor)?;
            budget.push(out, &ty)?;
            budget.push(out, ".class")
        }
        AnnotationValue::Annotation(annotation) => {
            render_annotation(annotation, resolver, depth + 1, out, budget)
        }
        AnnotationValue::Array(values) => {
            budget.push_char(out, '{')?;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    budget.push(out, ", ")?;
                }
                render_value(value, resolver, depth + 1, out, budget)?;
            }
            budget.push_char(out, '}')
        }
    }
}

fn render_annotation(
    annotation: &Annotation,
    resolver: &AnnotationNameResolver,
    depth: usize,
    out: &mut String,
    budget: &mut AnnotationRenderBudget,
) -> Option<()> {
    if depth >= MAX_ANNOTATION_DEPTH {
        return None;
    }
    let type_name: String = object_descriptor_source(resolver, &annotation.type_descriptor)?;
    budget.push_char(out, '@')?;
    budget.push(out, &type_name)?;
    if annotation.elements.is_empty() {
        return Some(());
    }
    budget.push_char(out, '(')?;
    for (index, element) in annotation.elements.iter().enumerate() {
        if !crate::name_disambig::is_java_source_identifier(&element.name) {
            return None;
        }
        if index > 0 {
            budget.push(out, ", ")?;
        }
        budget.push(out, &element.name)?;
        budget.push(out, " = ")?;
        render_value(&element.value, resolver, depth + 1, out, budget)?;
    }
    budget.push_char(out, ')')
}

fn render_outcome(
    outcome: &AnnotationOutcome,
    resolver: &AnnotationNameResolver,
    indent: &str,
    budget: &mut AnnotationRenderBudget,
) -> String {
    match outcome {
        AnnotationOutcome::Absent => String::new(),
        AnnotationOutcome::Rejected { instances, reasons } => {
            crate::debug::dbg_kv("annotation-reject", || reasons.join("; "));
            let mut out: String = String::new();
            for _ in 0..*instances {
                if budget.push(&mut out, indent).is_none()
                    || budget.push(&mut out, UNRESOLVED_ANNOTATION).is_none()
                    || budget.push_char(&mut out, '\n').is_none()
                {
                    break;
                }
            }
            out
        }
        AnnotationOutcome::Parsed(annotations) => {
            let mut scratch: String = String::new();
            let bytes_before: usize = budget.bytes_remaining;
            for annotation in annotations {
                if budget.push(&mut scratch, indent).is_none()
                    || render_annotation(annotation, resolver, 0, &mut scratch, budget).is_none()
                    || budget.push_char(&mut scratch, '\n').is_none()
                {
                    budget.bytes_remaining = bytes_before;
                    let mut rejected: String = String::new();
                    if budget.push(&mut rejected, indent).is_some()
                        && budget.push(&mut rejected, UNRESOLVED_ANNOTATION).is_some()
                        && budget.push_char(&mut rejected, '\n').is_some()
                    {
                        return rejected;
                    }
                    return String::new();
                }
            }
            scratch
        }
    }
}

#[must_use]
#[cfg(test)]
pub(crate) fn render_declaration_annotations(
    cf: &ClassFile,
    annotations: &DeclarationAnnotations,
    indent: &str,
) -> String {
    let mut budget: AnnotationRenderBudget = AnnotationRenderBudget::new();
    let requires_names: bool = matches!(&annotations.visible, AnnotationOutcome::Parsed(_))
        || matches!(&annotations.invisible, AnnotationOutcome::Parsed(_));
    let resolver: AnnotationNameResolver = if requires_names {
        AnnotationNameResolver::new(cf)
    } else {
        AnnotationNameResolver {
            inner_classes: BTreeMap::new(),
            resolution_bytes: Cell::new(MAX_ANNOTATION_TEXT_BYTES),
            resolution_steps: Cell::new(MAX_ANNOTATION_NODES),
            usable: true,
        }
    };
    let mut out: String = render_outcome(&annotations.visible, &resolver, indent, &mut budget);
    out.push_str(&render_outcome(
        &annotations.invisible,
        &resolver,
        indent,
        &mut budget,
    ));
    out
}

pub(crate) struct DeclarationAnnotationRenderer {
    parse_budget: AnnotationParseBudget,
    render_budget: AnnotationRenderBudget,
    resolver: AnnotationNameResolver,
}

impl DeclarationAnnotationRenderer {
    pub(crate) fn new(cf: &ClassFile) -> Self {
        Self {
            parse_budget: AnnotationParseBudget::new(),
            render_budget: AnnotationRenderBudget::new(),
            resolver: AnnotationNameResolver::new(cf),
        }
    }

    pub(crate) fn render(
        &mut self,
        cf: &ClassFile,
        attributes: &[Attribute],
        indent: &str,
    ) -> String {
        let annotations: DeclarationAnnotations =
            parse_declaration_annotations_with_budget(cf, attributes, &mut self.parse_budget);
        let mut out: String = render_outcome(
            &annotations.visible,
            &self.resolver,
            indent,
            &mut self.render_budget,
        );
        out.push_str(&render_outcome(
            &annotations.invisible,
            &self.resolver,
            indent,
            &mut self.render_budget,
        ));
        out
    }
}

fn read_u8(reader: &mut ByteReader<'_>, reason: &'static str) -> AnnotationResult<u8> {
    reader.read_u8().map_err(|_| AnnotationError(reason))
}

fn read_u16(reader: &mut ByteReader<'_>, reason: &'static str) -> AnnotationResult<u16> {
    reader.read_u16_be().map_err(|_| AnnotationError(reason))
}

fn reserve<T>(values: &mut Vec<T>, additional: usize) -> AnnotationResult<()> {
    values
        .try_reserve(additional)
        .map_err(|_| AnnotationError("annotation allocation failed"))
}

fn cp_entry(cf: &ClassFile, index: u16) -> AnnotationResult<&ConstantPoolEntry> {
    if index == 0 {
        return Err(AnnotationError("zero annotation constant-pool index"));
    }
    match cf.constant_pool.get(usize::from(index)) {
        Some(ConstantPoolEntry::Placeholder) | None => {
            Err(AnnotationError("invalid annotation constant-pool index"))
        }
        Some(entry) => Ok(entry),
    }
}

fn cp_utf8(
    cf: &ClassFile,
    index: u16,
    budget: &mut AnnotationParseBudget,
    reason: &'static str,
) -> AnnotationResult<String> {
    let ConstantPoolEntry::Utf8(value) = cp_entry(cf, index)? else {
        return Err(AnnotationError(reason));
    };
    budget.charge_text(value.len())?;
    Ok(value.clone())
}

fn integer_constant(cf: &ClassFile, index: u16) -> AnnotationResult<i32> {
    let ConstantPoolEntry::Integer(value) = cp_entry(cf, index)? else {
        return Err(AnnotationError("annotation constant is not an integer"));
    };
    Ok(*value)
}

fn parse_annotation(
    cf: &ClassFile,
    reader: &mut ByteReader<'_>,
    depth: usize,
    budget: &mut AnnotationParseBudget,
) -> AnnotationResult<Annotation> {
    if depth >= MAX_ANNOTATION_DEPTH {
        return Err(AnnotationError("annotation nesting quota exceeded"));
    }
    budget.charge_node()?;
    let type_index: u16 = read_u16(reader, "truncated annotation type index")?;
    let type_descriptor: String = cp_utf8(
        cf,
        type_index,
        budget,
        "annotation type is not a UTF-8 descriptor",
    )?;
    if !valid_jvm_object_descriptor(&type_descriptor) {
        return Err(AnnotationError("invalid annotation type descriptor"));
    }
    let pair_count: usize =
        usize::from(read_u16(reader, "truncated annotation element-pair count")?);
    if pair_count > budget.nodes {
        return Err(AnnotationError("annotation node quota exceeded"));
    }
    if pair_count > reader.remaining() / 5 || pair_count > budget.nodes / 2 {
        return Err(AnnotationError("invalid annotation element-pair count"));
    }
    let mut elements: Vec<AnnotationElement> = Vec::new();
    let mut names: BTreeSet<String> = BTreeSet::new();
    reserve(&mut elements, pair_count)?;
    for _ in 0..pair_count {
        budget.charge_node()?;
        let name_index: u16 = read_u16(reader, "truncated annotation element name")?;
        let name: String = cp_utf8(
            cf,
            name_index,
            budget,
            "annotation element name is not UTF-8",
        )?;
        if !valid_jvm_method_name(&name) {
            return Err(AnnotationError("invalid annotation element name"));
        }
        if !names.insert(name.clone()) {
            return Err(AnnotationError("duplicate annotation element name"));
        }
        let value: AnnotationValue = parse_annotation_value(cf, reader, depth + 1, budget)?;
        elements.push(AnnotationElement { name, value });
    }
    Ok(Annotation {
        type_descriptor,
        elements,
    })
}

fn parse_annotation_value(
    cf: &ClassFile,
    reader: &mut ByteReader<'_>,
    depth: usize,
    budget: &mut AnnotationParseBudget,
) -> AnnotationResult<AnnotationValue> {
    if depth >= MAX_ANNOTATION_DEPTH {
        return Err(AnnotationError("annotation nesting quota exceeded"));
    }
    budget.charge_node()?;
    let tag: u8 = read_u8(reader, "truncated annotation value tag")?;
    match tag {
        b'B' => {
            let index: u16 = read_u16(reader, "truncated byte annotation constant")?;
            let bytes: [u8; 4] = integer_constant(cf, index)?.to_be_bytes();
            let value: i8 = i8::from_be_bytes([bytes[3]]);
            Ok(AnnotationValue::Byte(value))
        }
        b'C' => {
            let index: u16 = read_u16(reader, "truncated char annotation constant")?;
            let bytes: [u8; 4] = integer_constant(cf, index)?.to_be_bytes();
            let value: u16 = u16::from_be_bytes([bytes[2], bytes[3]]);
            Ok(AnnotationValue::Char(value))
        }
        b'D' => {
            let index: u16 = read_u16(reader, "truncated double annotation constant")?;
            let ConstantPoolEntry::Double(bits) = cp_entry(cf, index)? else {
                return Err(AnnotationError("annotation constant is not a double"));
            };
            Ok(AnnotationValue::Double(*bits))
        }
        b'F' => {
            let index: u16 = read_u16(reader, "truncated float annotation constant")?;
            let ConstantPoolEntry::Float(bits) = cp_entry(cf, index)? else {
                return Err(AnnotationError("annotation constant is not a float"));
            };
            Ok(AnnotationValue::Float(*bits))
        }
        b'I' => {
            let index: u16 = read_u16(reader, "truncated int annotation constant")?;
            Ok(AnnotationValue::Int(integer_constant(cf, index)?))
        }
        b'J' => {
            let index: u16 = read_u16(reader, "truncated long annotation constant")?;
            let ConstantPoolEntry::Long(value) = cp_entry(cf, index)? else {
                return Err(AnnotationError("annotation constant is not a long"));
            };
            Ok(AnnotationValue::Long(*value))
        }
        b'S' => {
            let index: u16 = read_u16(reader, "truncated short annotation constant")?;
            let bytes: [u8; 4] = integer_constant(cf, index)?.to_be_bytes();
            let value: i16 = i16::from_be_bytes([bytes[2], bytes[3]]);
            Ok(AnnotationValue::Short(value))
        }
        b'Z' => {
            let index: u16 = read_u16(reader, "truncated boolean annotation constant")?;
            let value: bool = integer_constant(cf, index)? != 0;
            Ok(AnnotationValue::Boolean(value))
        }
        b's' => {
            let index: u16 = read_u16(reader, "truncated string annotation constant")?;
            Ok(AnnotationValue::String(cp_utf8(
                cf,
                index,
                budget,
                "string annotation constant is not UTF-8",
            )?))
        }
        b'e' => {
            let type_index: u16 = read_u16(reader, "truncated enum annotation type")?;
            let name_index: u16 = read_u16(reader, "truncated enum annotation constant")?;
            let type_descriptor: String =
                cp_utf8(cf, type_index, budget, "enum annotation type is not UTF-8")?;
            if !valid_jvm_object_descriptor(&type_descriptor) {
                return Err(AnnotationError("invalid enum annotation descriptor"));
            }
            let constant_name: String = cp_utf8(
                cf,
                name_index,
                budget,
                "enum annotation constant name is not UTF-8",
            )?;
            if !valid_jvm_unqualified_name(&constant_name) {
                return Err(AnnotationError("invalid enum annotation constant name"));
            }
            Ok(AnnotationValue::Enum {
                type_descriptor,
                constant_name,
            })
        }
        b'c' => {
            let index: u16 = read_u16(reader, "truncated class annotation literal")?;
            let type_descriptor: String = cp_utf8(
                cf,
                index,
                budget,
                "class annotation literal is not a UTF-8 descriptor",
            )?;
            if !valid_jvm_class_descriptor(&type_descriptor) {
                return Err(AnnotationError("invalid class annotation descriptor"));
            }
            Ok(AnnotationValue::Class(type_descriptor))
        }
        b'@' => Ok(AnnotationValue::Annotation(Box::new(parse_annotation(
            cf,
            reader,
            depth + 1,
            budget,
        )?))),
        b'[' => {
            let count: usize = usize::from(read_u16(reader, "truncated annotation array length")?);
            if count > budget.nodes {
                return Err(AnnotationError("annotation node quota exceeded"));
            }
            if count > reader.remaining() / 3 {
                return Err(AnnotationError("invalid annotation array length"));
            }
            let mut values: Vec<AnnotationValue> = Vec::new();
            reserve(&mut values, count)?;
            for _ in 0..count {
                values.push(parse_annotation_value(cf, reader, depth + 1, budget)?);
            }
            Ok(AnnotationValue::Array(values))
        }
        _ => Err(AnnotationError("unknown annotation value tag")),
    }
}

fn parse_annotation_attribute(
    cf: &ClassFile,
    attr: &Attribute,
    budget: &mut AnnotationParseBudget,
) -> AnnotationResult<Vec<Annotation>> {
    let mut reader: ByteReader<'_> = ByteReader::new(&attr.info);
    let count: usize = usize::from(read_u16(
        &mut reader,
        "truncated declaration annotation count",
    )?);
    if count > budget.nodes {
        return Err(AnnotationError("annotation node quota exceeded"));
    }
    if count > reader.remaining() / 4 {
        return Err(AnnotationError("invalid declaration annotation count"));
    }
    let mut annotations: Vec<Annotation> = Vec::new();
    reserve(&mut annotations, count)?;
    for _ in 0..count {
        annotations.push(parse_annotation(cf, &mut reader, 0, budget)?);
    }
    if reader.remaining() != 0 {
        return Err(AnnotationError(
            "trailing bytes in declaration annotation attribute",
        ));
    }
    Ok(annotations)
}

fn parse_annotation_bucket(
    cf: &ClassFile,
    attributes: &[Attribute],
    attribute_name: &str,
    budget: &mut AnnotationParseBudget,
) -> AnnotationOutcome {
    let mut first: Option<&Attribute> = None;
    let mut instances: usize = 0;
    let mut reasons: Vec<String> = Vec::new();
    for attr in attributes {
        if !cf
            .utf8_at(attr.name_index)
            .is_ok_and(|name: &str| name == attribute_name)
        {
            continue;
        }
        instances += 1;
        if first.is_none() {
            first = Some(attr);
        }
        if let Err(error) = budget.charge_input(attr.info.len()) {
            reasons.push(error.to_string());
        }
    }
    if instances == 0 {
        return AnnotationOutcome::Absent;
    }
    if instances > 1 {
        reasons.push(format!(
            "DR-JVM-0034: malformed declaration annotation attribute: duplicate {attribute_name} attributes"
        ));
    }
    if !reasons.is_empty() {
        return AnnotationOutcome::Rejected { instances, reasons };
    }
    let Some(attr): Option<&Attribute> = first else {
        return AnnotationOutcome::Rejected {
            instances,
            reasons: vec!["DR-JVM-0034: annotation attribute lookup failed".to_string()],
        };
    };
    match parse_annotation_attribute(cf, attr, budget) {
        Ok(annotations) => AnnotationOutcome::Parsed(annotations),
        Err(error) => AnnotationOutcome::Rejected {
            instances,
            reasons: vec![error.to_string()],
        },
    }
}

#[must_use]
pub(crate) fn parse_declaration_annotations(cf: &ClassFile) -> DeclarationAnnotations {
    parse_declaration_annotations_from(cf, &cf.attributes)
}

#[must_use]
pub(crate) fn parse_declaration_annotations_from(
    cf: &ClassFile,
    attributes: &[Attribute],
) -> DeclarationAnnotations {
    let mut budget: AnnotationParseBudget = AnnotationParseBudget::new();
    parse_declaration_annotations_with_budget(cf, attributes, &mut budget)
}

fn parse_declaration_annotations_with_budget(
    cf: &ClassFile,
    attributes: &[Attribute],
    budget: &mut AnnotationParseBudget,
) -> DeclarationAnnotations {
    DeclarationAnnotations {
        visible: parse_annotation_bucket(cf, attributes, "RuntimeVisibleAnnotations", budget),
        invisible: parse_annotation_bucket(cf, attributes, "RuntimeInvisibleAnnotations", budget),
    }
}

fn annotation_value_matches_type(value: &AnnotationValue, ty: &JavaType) -> bool {
    match (value, ty) {
        (AnnotationValue::Byte(_), JavaType::Byte)
        | (AnnotationValue::Char(_), JavaType::Char)
        | (AnnotationValue::Double(_), JavaType::Double)
        | (AnnotationValue::Float(_), JavaType::Float)
        | (AnnotationValue::Int(_), JavaType::Int)
        | (AnnotationValue::Long(_), JavaType::Long)
        | (AnnotationValue::Short(_), JavaType::Short)
        | (AnnotationValue::Boolean(_), JavaType::Boolean) => true,
        (AnnotationValue::String(_), JavaType::Object(descriptor_text)) => {
            descriptor_text == "Ljava/lang/String;"
        }
        (
            AnnotationValue::Enum {
                type_descriptor, ..
            },
            JavaType::Object(descriptor_text),
        ) => type_descriptor == descriptor_text,
        (AnnotationValue::Class(_), JavaType::Object(descriptor_text)) => {
            descriptor_text == "Ljava/lang/Class;"
        }
        (AnnotationValue::Annotation(annotation), JavaType::Object(descriptor_text)) => {
            annotation.type_descriptor == *descriptor_text
        }
        (AnnotationValue::Array(values), JavaType::Array(inner))
            if !matches!(inner.as_ref(), JavaType::Array(_) | JavaType::Void) =>
        {
            values
                .iter()
                .all(|value: &AnnotationValue| annotation_value_matches_type(value, inner))
        }
        _ => false,
    }
}

#[must_use]
pub(crate) fn render_annotation_defaults(cf: &ClassFile) -> BTreeMap<usize, String> {
    let has_defaults: bool = cf.methods.iter().any(|method: &MethodInfo| {
        method.attributes.iter().any(|attr: &Attribute| {
            cf.utf8_at(attr.name_index)
                .is_ok_and(|name: &str| name == "AnnotationDefault")
        })
    });
    if !has_defaults {
        return BTreeMap::new();
    }
    let resolver: AnnotationNameResolver = AnnotationNameResolver::new(cf);
    let mut parse_budget: AnnotationParseBudget = AnnotationParseBudget::new();
    let mut render_budget: AnnotationRenderBudget = AnnotationRenderBudget::new();
    let mut defaults: BTreeMap<usize, String> = BTreeMap::new();
    let mut return_types: BTreeMap<u16, Option<JavaType>> = BTreeMap::new();
    for (method_index, method) in cf.methods.iter().enumerate() {
        let mut first: Option<&Attribute> = None;
        let mut instances: usize = 0;
        let mut input_valid: bool = true;
        for attr in &method.attributes {
            if !cf
                .utf8_at(attr.name_index)
                .is_ok_and(|name: &str| name == "AnnotationDefault")
            {
                continue;
            }
            instances += 1;
            if first.is_none() {
                first = Some(attr);
            }
            input_valid &= parse_budget.charge_input(attr.info.len()).is_ok();
        }
        if instances == 0 {
            continue;
        }
        let Some(attr): Option<&Attribute> = first else {
            defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
            continue;
        };
        if instances != 1 || !input_valid {
            defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
            continue;
        }
        if method.attributes.iter().any(|attr: &Attribute| {
            cf.utf8_at(attr.name_index)
                .is_ok_and(|name: &str| name == "Code")
        }) {
            defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
            continue;
        }
        let mut reader: ByteReader<'_> = ByteReader::new(&attr.info);
        let value: AnnotationValue =
            match parse_annotation_value(cf, &mut reader, 0, &mut parse_budget) {
                Ok(value) if reader.remaining() == 0 => value,
                Ok(_) | Err(_) => {
                    defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
                    continue;
                }
            };
        if let std::collections::btree_map::Entry::Vacant(entry) =
            return_types.entry(method.descriptor_index)
        {
            let return_type: Option<JavaType> = cf
                .utf8_at(method.descriptor_index)
                .ok()
                .filter(|descriptor_text: &&str| {
                    parse_budget.charge_text(descriptor_text.len()).is_ok()
                })
                .and_then(descriptor::parse_method)
                .filter(|method_descriptor| method_descriptor.params.is_empty())
                .map(|method_descriptor| method_descriptor.returns);
            entry.insert(return_type);
        }
        let Some(return_type): Option<&JavaType> = return_types
            .get(&method.descriptor_index)
            .and_then(Option::as_ref)
        else {
            defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
            continue;
        };
        if !annotation_value_matches_type(&value, return_type) {
            defaults.insert(method_index, UNRESOLVED_ANNOTATION_VALUE.to_string());
            continue;
        }
        let mut rendered: String = String::new();
        if render_value(&value, &resolver, 0, &mut rendered, &mut render_budget).is_none() {
            rendered = UNRESOLVED_ANNOTATION_VALUE.to_string();
        }
        defaults.insert(method_index, rendered);
    }
    defaults
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapMethod {
    pub method_ref_index: u16,
    pub arguments: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordComponent {
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassStructure {
    pub bootstrap_methods: Vec<BootstrapMethod>,
    pub record_components: Vec<RecordComponent>,
    pub permitted_subclasses: Vec<String>,
    pub nest_host: Option<String>,
    pub nest_members: Vec<String>,
    pub source_file: Option<String>,
    pub signature: Option<String>,
    pub is_record: bool,
    pub is_sealed: bool,
}

#[inline]
fn be_u16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}

#[inline]
fn be_u32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

#[must_use]
pub fn analyze(cf: &ClassFile) -> ClassStructure {
    let mut out: ClassStructure = ClassStructure::default();
    for attr in &cf.attributes {
        let Ok(name): core::result::Result<&str, _> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        match name {
            "BootstrapMethods" => out.bootstrap_methods = parse_bootstrap_methods(&attr.info),
            "Record" => {
                out.record_components = parse_record(cf, attr);
                out.is_record = true;
            }
            "PermittedSubclasses" => {
                out.permitted_subclasses = parse_class_index_list(cf, &attr.info);
                out.is_sealed = true;
            }
            "NestHost" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.nest_host = cf.class_name(idx).ok().map(str::to_string);
                }
            }
            "NestMembers" => out.nest_members = parse_class_index_list(cf, &attr.info),
            "SourceFile" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.source_file = cf.utf8_at(idx).ok().map(str::to_string);
                }
            }
            "Signature" => {
                if let Some(idx) = be_u16(&attr.info, 0) {
                    out.signature = cf.utf8_at(idx).ok().map(str::to_string);
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_bootstrap_methods(info: &[u8]) -> Vec<BootstrapMethod> {
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<BootstrapMethod> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let (Some(method_ref_index), Some(num_args)): (Option<u16>, Option<u16>) =
            (be_u16(info, pos), be_u16(info, pos + 2))
        else {
            break;
        };
        pos += 4;
        let arg_count: usize = usize::from(num_args);
        let mut arguments: Vec<u16> = Vec::with_capacity(arg_count.min(info.len()));
        for _ in 0..arg_count {
            let Some(arg): Option<u16> = be_u16(info, pos) else {
                break;
            };
            arguments.push(arg);
            pos += 2;
        }
        out.push(BootstrapMethod {
            method_ref_index,
            arguments,
        });
    }
    out
}

fn parse_record(cf: &ClassFile, attr: &Attribute) -> Vec<RecordComponent> {
    let info: &[u8] = &attr.info;
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<RecordComponent> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let (Some(name_idx), Some(desc_idx), Some(attr_count)): (
            Option<u16>,
            Option<u16>,
            Option<u16>,
        ) = (
            be_u16(info, pos),
            be_u16(info, pos + 2),
            be_u16(info, pos + 4),
        ) else {
            break;
        };
        pos += 6;
        let name: String = cf.utf8_at(name_idx).unwrap_or("?").to_string();
        let descriptor: String = cf.utf8_at(desc_idx).unwrap_or("?").to_string();
        out.push(RecordComponent { name, descriptor });
        for _ in 0..attr_count {
            let Some(_inner_name): Option<u16> = be_u16(info, pos) else {
                break;
            };
            let Some(inner_len): Option<u32> = be_u32(info, pos + 2) else {
                break;
            };
            pos = pos.saturating_add(6).saturating_add(inner_len as usize);
        }
    }
    out
}

fn parse_class_index_list(cf: &ClassFile, info: &[u8]) -> Vec<String> {
    let Some(count): Option<u16> = be_u16(info, 0) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::with_capacity(usize::from(count).min(info.len()));
    let mut pos: usize = 2;
    for _ in 0..count {
        let Some(idx): Option<u16> = be_u16(info, pos) else {
            break;
        };
        if let Ok(name) = cf.class_name(idx) {
            out.push(name.to_string());
        }
        pos += 2;
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::classfile::ConstantPoolEntry;

    fn class_with(attrs: Vec<Attribute>, cp: Vec<ConstantPoolEntry>) -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 61,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: attrs,
        }
    }

    #[test]
    fn detects_record_components() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("Record".into()));
        cp.push(ConstantPoolEntry::Utf8("x".into()));
        cp.push(ConstantPoolEntry::Utf8("I".into()));
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        info.extend_from_slice(&0u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert!(s.is_record);
        assert_eq!(s.record_components.len(), 1);
        assert_eq!(s.record_components[0].name, "x");
        assert_eq!(s.record_components[0].descriptor, "I");
    }

    #[test]
    fn detects_sealed_permitted_subclasses() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("PermittedSubclasses".into()));
        cp.push(ConstantPoolEntry::Utf8("com/example/Impl".into()));
        cp.push(ConstantPoolEntry::Class { name_index: 2 });
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert!(s.is_sealed);
        assert_eq!(s.permitted_subclasses, vec!["com/example/Impl".to_string()]);
    }

    #[test]
    fn parses_bootstrap_methods() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("BootstrapMethods".into()));
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&5u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&7u16.to_be_bytes());
        info.extend_from_slice(&8u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert_eq!(s.bootstrap_methods.len(), 1);
        assert_eq!(s.bootstrap_methods[0].method_ref_index, 5);
        assert_eq!(s.bootstrap_methods[0].arguments, vec![7, 8]);
    }

    #[test]
    fn captures_nest_host() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("NestHost".into()));
        cp.push(ConstantPoolEntry::Utf8("com/example/Outer".into()));
        cp.push(ConstantPoolEntry::Class { name_index: 2 });
        let info: Vec<u8> = 3u16.to_be_bytes().to_vec();
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let s: ClassStructure = analyze(&cf);
        assert_eq!(s.nest_host.as_deref(), Some("com/example/Outer"));
    }

    #[test]
    fn rejects_duplicate_and_redirecting_inner_class_names() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("InnerClasses".into()),
            ConstantPoolEntry::Utf8("pkg/Outer$Inner".into()),
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("pkg/Outer".into()),
            ConstantPoolEntry::Class { name_index: 4 },
            ConstantPoolEntry::Utf8("Inner".into()),
            ConstantPoolEntry::Utf8("Fake".into()),
            ConstantPoolEntry::Class { name_index: 2 },
            ConstantPoolEntry::Utf8("pkg/Outer$1".into()),
            ConstantPoolEntry::Class { name_index: 9 },
        ];
        let mut redirected_info: Vec<u8> = Vec::new();
        redirected_info.extend_from_slice(&1u16.to_be_bytes());
        for index in [3u16, 5, 7, 0] {
            redirected_info.extend_from_slice(&index.to_be_bytes());
        }
        let redirected: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: redirected_info,
            }],
            cp.clone(),
        );
        assert!(!AnnotationNameResolver::new(&redirected).usable);

        let mut duplicate_info: Vec<u8> = Vec::new();
        duplicate_info.extend_from_slice(&2u16.to_be_bytes());
        for _ in 0..2 {
            for index in [3u16, 5, 6, 0] {
                duplicate_info.extend_from_slice(&index.to_be_bytes());
            }
        }
        let duplicate: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: duplicate_info,
            }],
            cp.clone(),
        );
        assert!(!AnnotationNameResolver::new(&duplicate).usable);

        let mut alias_info: Vec<u8> = Vec::new();
        alias_info.extend_from_slice(&2u16.to_be_bytes());
        for inner_index in [3u16, 8] {
            for index in [inner_index, 5, 6, 1] {
                alias_info.extend_from_slice(&index.to_be_bytes());
            }
        }
        let alias: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: alias_info,
            }],
            cp.clone(),
        );
        assert!(AnnotationNameResolver::new(&alias).usable);
        let alias_entries: InnerClassesAttribute = parse_inner_classes(&alias);
        assert!(matches!(
            alias_entries,
            InnerClassesAttribute::Parsed(entries) if entries.len() == 1
        ));

        let mut self_info: Vec<u8> = Vec::new();
        self_info.extend_from_slice(&1u16.to_be_bytes());
        for index in [3u16, 3, 6, 0] {
            self_info.extend_from_slice(&index.to_be_bytes());
        }
        let self_owned: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: self_info,
            }],
            cp.clone(),
        );
        assert!(matches!(
            parse_inner_classes(&self_owned),
            InnerClassesAttribute::Rejected
        ));

        let mut anonymous_outer_info: Vec<u8> = Vec::new();
        anonymous_outer_info.extend_from_slice(&1u16.to_be_bytes());
        for index in [10u16, 5, 0, 0] {
            anonymous_outer_info.extend_from_slice(&index.to_be_bytes());
        }
        let anonymous_outer: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: anonymous_outer_info,
            }],
            cp,
        );
        assert!(matches!(
            parse_inner_classes(&anonymous_outer),
            InnerClassesAttribute::Rejected
        ));
    }

    fn push_constant_pair(info: &mut Vec<u8>, name_index: u16, tag: u8, value_index: u16) {
        info.extend_from_slice(&name_index.to_be_bytes());
        info.push(tag);
        info.extend_from_slice(&value_index.to_be_bytes());
    }

    #[test]
    fn parses_and_renders_every_declaration_annotation_value_tag() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("Lpkg/All;".into()),
            ConstantPoolEntry::Utf8("b".into()),
            ConstantPoolEntry::Integer(128),
            ConstantPoolEntry::Utf8("c".into()),
            ConstantPoolEntry::Integer(-1),
            ConstantPoolEntry::Utf8("d".into()),
            ConstantPoolEntry::Double(1.5f64.to_bits()),
            ConstantPoolEntry::Utf8("f".into()),
            ConstantPoolEntry::Float(2.5f32.to_bits()),
            ConstantPoolEntry::Utf8("i".into()),
            ConstantPoolEntry::Integer(i32::MIN),
            ConstantPoolEntry::Utf8("j".into()),
            ConstantPoolEntry::Long(i64::MIN),
            ConstantPoolEntry::Utf8("s".into()),
            ConstantPoolEntry::Integer(98_304),
            ConstantPoolEntry::Utf8("z".into()),
            ConstantPoolEntry::Integer(2),
            ConstantPoolEntry::Utf8("text".into()),
            ConstantPoolEntry::Utf8("hello\n".into()),
            ConstantPoolEntry::Utf8("e".into()),
            ConstantPoolEntry::Utf8("Lpkg/E;".into()),
            ConstantPoolEntry::Utf8("HIGH".into()),
            ConstantPoolEntry::Utf8("type".into()),
            ConstantPoolEntry::Utf8("Ljava/lang/String;".into()),
            ConstantPoolEntry::Utf8("nested".into()),
            ConstantPoolEntry::Utf8("Lpkg/Nested;".into()),
            ConstantPoolEntry::Utf8("value".into()),
            ConstantPoolEntry::Utf8("inside".into()),
            ConstantPoolEntry::Utf8("array".into()),
            ConstantPoolEntry::Integer(1),
            ConstantPoolEntry::Integer(2),
        ];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&13u16.to_be_bytes());
        for (name_index, tag, value_index) in [
            (3, b'B', 4),
            (5, b'C', 6),
            (7, b'D', 8),
            (9, b'F', 10),
            (11, b'I', 12),
            (13, b'J', 14),
            (15, b'S', 16),
            (17, b'Z', 18),
            (19, b's', 20),
        ] {
            push_constant_pair(&mut info, name_index, tag, value_index);
        }
        info.extend_from_slice(&21u16.to_be_bytes());
        info.push(b'e');
        info.extend_from_slice(&22u16.to_be_bytes());
        info.extend_from_slice(&23u16.to_be_bytes());
        push_constant_pair(&mut info, 24, b'c', 25);
        info.extend_from_slice(&26u16.to_be_bytes());
        info.push(b'@');
        info.extend_from_slice(&27u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        push_constant_pair(&mut info, 28, b's', 29);
        info.extend_from_slice(&30u16.to_be_bytes());
        info.push(b'[');
        info.extend_from_slice(&2u16.to_be_bytes());
        info.push(b'I');
        info.extend_from_slice(&31u16.to_be_bytes());
        info.push(b'I');
        info.extend_from_slice(&32u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let declarations: DeclarationAnnotations = parse_declaration_annotations(&cf);
        let resolver: AnnotationNameResolver = AnnotationNameResolver::new(&cf);
        let annotations: Vec<Annotation> = match declarations.visible {
            AnnotationOutcome::Parsed(annotations) => Some(annotations),
            _ => None,
        }
        .expect("valid annotation attribute was rejected");
        assert_eq!(annotations.len(), 1);
        let mut rendered: String = String::new();
        let mut budget: AnnotationRenderBudget = AnnotationRenderBudget::new();
        render_annotation(&annotations[0], &resolver, 0, &mut rendered, &mut budget)
            .expect("valid annotation did not render");
        assert_eq!(
            rendered,
            "@pkg.All(b = (byte) -128, c = (char) 65535, d = 1.5, f = 2.5f, i = -2147483648, j = -9223372036854775808L, s = (short) -32768, z = true, text = \"hello\\n\", e = pkg.E.HIGH, type = java.lang.String.class, nested = @pkg.Nested(value = \"inside\"), array = {1, 2})"
        );
        assert_eq!(
            float_literal(f32::NAN.to_bits()).as_deref(),
            Some("(0.0f / 0.0f)")
        );
        assert_eq!(
            double_literal(f64::NAN.to_bits()).as_deref(),
            Some("(0.0 / 0.0)")
        );
        assert_eq!(float_literal(f32::NAN.to_bits() ^ 1), None);
        assert_eq!(double_literal(f64::NAN.to_bits() ^ 1), None);
        assert_eq!(
            object_descriptor_source(&resolver, "Lpkg/A$B;").as_deref(),
            Some("pkg.A$B")
        );
        assert_eq!(object_descriptor_source(&resolver, "Lpkg/Bad-Name;"), None);
        assert_eq!(object_descriptor_source(&resolver, "Lpkg/class;"), None);
        assert_eq!(object_descriptor_source(&resolver, "Lpkg/record;"), None);
        let mut invisible_cf: ClassFile = cf;
        let invisible_name_index: u16 =
            u16::try_from(invisible_cf.constant_pool.len()).expect("constant-pool index");
        invisible_cf.constant_pool.push(ConstantPoolEntry::Utf8(
            "RuntimeInvisibleAnnotations".into(),
        ));
        invisible_cf.attributes[0].name_index = invisible_name_index;
        let invisible: DeclarationAnnotations = parse_declaration_annotations(&invisible_cf);
        assert!(matches!(&invisible.visible, AnnotationOutcome::Absent));
        assert!(matches!(&invisible.invisible, AnnotationOutcome::Parsed(_)));
        assert_eq!(
            render_declaration_annotations(&invisible_cf, &invisible, ""),
            format!("{rendered}\n")
        );
    }

    #[test]
    fn source_unrepresentable_bucket_emits_one_marker_without_hiding_valid_sibling() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("RuntimeInvisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("Lpkg/Ok;".into()),
            ConstantPoolEntry::Utf8("class".into()),
            ConstantPoolEntry::Integer(1),
        ];
        let mut visible: Vec<u8> = Vec::new();
        visible.extend_from_slice(&1u16.to_be_bytes());
        visible.extend_from_slice(&3u16.to_be_bytes());
        visible.extend_from_slice(&0u16.to_be_bytes());
        let mut invisible: Vec<u8> = Vec::new();
        invisible.extend_from_slice(&1u16.to_be_bytes());
        invisible.extend_from_slice(&3u16.to_be_bytes());
        invisible.extend_from_slice(&1u16.to_be_bytes());
        push_constant_pair(&mut invisible, 4, b'I', 5);
        let cf: ClassFile = class_with(
            vec![
                Attribute {
                    name_index: 1,
                    info: visible,
                },
                Attribute {
                    name_index: 2,
                    info: invisible,
                },
            ],
            cp,
        );
        let declarations: DeclarationAnnotations = parse_declaration_annotations(&cf);
        assert!(matches!(declarations.visible, AnnotationOutcome::Parsed(_)));
        assert!(matches!(
            &declarations.invisible,
            AnnotationOutcome::Parsed(_)
        ));
        assert_eq!(
            render_declaration_annotations(&cf, &declarations, ""),
            "@pkg.Ok\n@<unresolved-annotation>\n"
        );
    }

    #[test]
    fn truncated_declaration_annotation_is_rejected() {
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info: 1u16.to_be_bytes().to_vec(),
            }],
            vec![
                ConstantPoolEntry::Placeholder,
                ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ],
        );
        let declarations: DeclarationAnnotations = parse_declaration_annotations(&cf);
        assert!(matches!(
            &declarations.visible,
            AnnotationOutcome::Rejected { instances: 1, .. }
        ));
        assert_eq!(
            render_declaration_annotations(&cf, &declarations, ""),
            "@<unresolved-annotation>\n"
        );
    }

    #[test]
    fn excessive_annotation_nesting_is_rejected() {
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("Lpkg/Deep;".into()),
            ConstantPoolEntry::Utf8("value".into()),
            ConstantPoolEntry::Integer(1),
        ];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&3u16.to_be_bytes());
        for _ in 0..MAX_ANNOTATION_DEPTH {
            info.push(b'[');
            info.extend_from_slice(&1u16.to_be_bytes());
        }
        info.push(b'I');
        info.extend_from_slice(&4u16.to_be_bytes());
        let cf: ClassFile = class_with(
            vec![Attribute {
                name_index: 1,
                info,
            }],
            cp,
        );
        let declarations: DeclarationAnnotations = parse_declaration_annotations(&cf);
        assert!(matches!(
            declarations.visible,
            AnnotationOutcome::Rejected { instances: 1, .. }
        ));
        assert_eq!(
            render_declaration_annotations(&cf, &declarations, ""),
            "@<unresolved-annotation>\n"
        );
    }

    #[test]
    fn declaration_annotation_budget_is_shared_across_members() {
        let large_value: String = "x".repeat(3 * 1024 * 1024);
        let cp: Vec<ConstantPoolEntry> = vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("RuntimeVisibleAnnotations".into()),
            ConstantPoolEntry::Utf8("Lpkg/Big;".into()),
            ConstantPoolEntry::Utf8("value".into()),
            ConstantPoolEntry::Utf8(large_value),
            ConstantPoolEntry::Utf8("Budgeted".into()),
            ConstantPoolEntry::Class { name_index: 5 },
            ConstantPoolEntry::Utf8("java/lang/Object".into()),
            ConstantPoolEntry::Class { name_index: 7 },
            ConstantPoolEntry::Utf8("field".into()),
            ConstantPoolEntry::Utf8("Ljava/lang/String;".into()),
            ConstantPoolEntry::Utf8("method".into()),
            ConstantPoolEntry::Utf8("()V".into()),
        ];
        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&1u16.to_be_bytes());
        info.extend_from_slice(&2u16.to_be_bytes());
        info.extend_from_slice(&1u16.to_be_bytes());
        push_constant_pair(&mut info, 3, b's', 4);
        let annotation: Attribute = Attribute {
            name_index: 1,
            info,
        };
        let mut cf: ClassFile = class_with(Vec::new(), cp);
        cf.access_flags = 0x0401;
        cf.this_class = 6;
        cf.super_class = 8;
        cf.fields = vec![crate::classfile::FieldInfo {
            access_flags: 0x0001,
            name_index: 9,
            descriptor_index: 10,
            attributes: vec![annotation.clone()],
        }];
        cf.methods = vec![MethodInfo {
            access_flags: 0x0401,
            name_index: 11,
            descriptor_index: 12,
            attributes: vec![annotation],
        }];
        let source: String = crate::decompile::decompile_class(&cf).source;
        assert!(source.len() > 3 * 1024 * 1024);
        assert!(source.contains("public String field;"));
        assert!(source.contains("@<unresolved-annotation>\n    public abstract void method();"));
        assert!(
            source.len()
                <= MAX_ANNOTATION_RENDER_BYTES
                    + "public abstract class Budgeted {\n    public String field;\n\n    public abstract void method();\n}\n"
                        .len()
                    + UNRESOLVED_ANNOTATION.len()
                    + 6
        );
    }
}
