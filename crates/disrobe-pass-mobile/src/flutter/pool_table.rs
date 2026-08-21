use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::aot_lift::escape_dart_string;
use super::cid_table::predefined_name;
use super::dart_graph::{
    DartGraphLimits, DartGraphNode, DartGraphNodeKind, DartParsedGraph, DartPoolSlot,
};
use super::dart_graph_inventory::DartPinnedInventory;
use super::dart_graph_layout::{DartClusterBodyKind, DartPinnedLayout};
use super::dart_graph_recovery::{DartPinnedGraph, parse_pinned_isolate_graph};
use crate::error::Result;

pub const DART_POOL_ELEMENT_BASE_BYTES: u64 = 16;

pub const DART_POOL_ENTRY_BYTES: u64 = 8;

#[must_use]
pub fn pool_slot_of_offset(byte_offset: u64) -> Option<u64> {
    let relative: u64 = byte_offset.checked_sub(DART_POOL_ELEMENT_BASE_BYTES)?;
    relative
        .is_multiple_of(DART_POOL_ENTRY_BYTES)
        .then_some(relative / DART_POOL_ENTRY_BYTES)
}

#[must_use]
pub const fn pool_offset_of_slot(slot: u64) -> u64 {
    DART_POOL_ELEMENT_BASE_BYTES.saturating_add(slot.saturating_mul(DART_POOL_ENTRY_BYTES))
}

const MINT_CLASS_ID: i32 = 61;

const IMMUTABLE_ARRAY_NAME: &str = "ImmutableArray";

const MAX_LITERAL_DEPTH: usize = 4;

const MAX_LIST_ELEMENTS: usize = 8;

const MAX_LITERAL_NODES: usize = 64;

const MAX_LITERAL_CHARS: usize = 120;

const SMALL_INTEGER_BOUND: i64 = 1 << 20;

const ELISION: &str = "...";

const TRUNCATED_STRING: &str = "truncatedString";

const TYPE_PARAMETER_PREFIX: &str = "typeParam@";

const RECORD_TYPE_TOKEN: &str = "recordType";

const NULL_OBJECT_REFERENCE: u32 = 1;

const SYMBOL_CLASS_NAME: &str = "Symbol";

const SYMBOL_LIBRARY_URI: &str = "dart:_internal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartPoolLiteralKind {
    Str,
    Double,
    Integer,
    List,
    Named,
    Type,
    TypeArguments,
    Symbol,
    RawImmediate,
    NativeFunction,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DartPoolObjectKind {
    Text,
    Mint,
    Double,
    List { immutable: bool },
    Class,
    Function,
    Field,
    Library,
    Type,
    TypeArguments,
    TypeParameter,
    RecordType,
    Symbol,
    Opaque,
}

#[derive(Debug, Clone)]
struct DartPoolObject {
    kind: DartPoolObjectKind,
    text: Option<String>,
    text_is_escaped: bool,
    immediate: Option<i64>,
    references: Vec<u32>,
    class_id: Option<i32>,
    type_flags: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPoolTableStats {
    pub slots: usize,
    pub literals: usize,
    pub tagged_objects: usize,
    pub raw_immediates: usize,
}

#[derive(Debug)]
pub struct DartPoolTable {
    slots: Vec<DartPoolSlot>,
    objects: Vec<DartPoolObject>,
    declarations: DartPinnedLayout,
    function_parameters: BTreeMap<String, Option<u8>>,
}

impl DartPoolTable {
    pub fn build(
        vm_data: &[u8],
        isolate_data: &[u8],
        limits: DartGraphLimits,
    ) -> Result<Option<Self>> {
        let Some(pinned): Option<DartPinnedGraph> =
            parse_pinned_isolate_graph(vm_data, isolate_data, limits)?
        else {
            return Ok(None);
        };
        let DartPinnedGraph {
            graph,
            layout,
            inventory,
        }: DartPinnedGraph = pinned;
        let DartParsedGraph { nodes, .. }: DartParsedGraph = graph;
        let Some(slots): Option<Vec<DartPoolSlot>> = widest_pool(&nodes) else {
            return Ok(None);
        };
        let function_parameters: BTreeMap<String, Option<u8>> =
            index_function_parameters(&inventory);
        let mut objects: Vec<DartPoolObject> = nodes
            .iter()
            .map(|node: &DartGraphNode| compact(node, layout))
            .collect::<Vec<DartPoolObject>>();
        classify_symbol_objects(&mut objects, layout);
        Ok(Some(Self {
            slots,
            objects,
            declarations: layout,
            function_parameters,
        }))
    }

    #[must_use]
    pub(super) fn function_parameter_count(&self, name: &str) -> Option<u8> {
        self.function_parameters.get(name).copied().flatten()
    }

    #[must_use]
    pub fn stats(&self) -> DartPoolTableStats {
        let mut object_slot_count: usize = 0;
        let mut immediate_slot_count: usize = 0;
        let mut literal_slot_count: usize = 0;
        for index in 0..self.slots.len() {
            match self.slots.get(index) {
                Some(DartPoolSlot::Object(_)) => object_slot_count += 1,
                Some(DartPoolSlot::Immediate(_)) => immediate_slot_count += 1,
                _ => {}
            }
            if self.render_slot(index, false).is_some() {
                literal_slot_count += 1;
            }
        }
        DartPoolTableStats {
            slots: self.slots.len(),
            literals: literal_slot_count,
            tagged_objects: object_slot_count,
            raw_immediates: immediate_slot_count,
        }
    }

    #[must_use]
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub fn slot_index(&self, byte_offset: u64) -> Option<usize> {
        let index: usize = usize::try_from(pool_slot_of_offset(byte_offset)?).ok()?;
        (index < self.slots.len()).then_some(index)
    }

    #[must_use]
    pub fn kind_at_offset(&self, byte_offset: u64, float: bool) -> DartPoolLiteralKind {
        let Some(index): Option<usize> = self.slot_index(byte_offset) else {
            return DartPoolLiteralKind::Unresolved;
        };
        match self.slots.get(index) {
            Some(DartPoolSlot::Immediate(_)) => {
                if float {
                    DartPoolLiteralKind::Double
                } else {
                    DartPoolLiteralKind::RawImmediate
                }
            }
            Some(DartPoolSlot::NativeFunction) => DartPoolLiteralKind::NativeFunction,
            Some(DartPoolSlot::Object(reference)) => self.object_kind(*reference),
            Some(DartPoolSlot::Unmodelled) | None => DartPoolLiteralKind::Unresolved,
        }
    }

    #[must_use]
    pub fn render_at_offset(&self, byte_offset: u64, float: bool) -> Option<String> {
        let index: usize = self.slot_index(byte_offset)?;
        self.render_slot(index, float)
    }

    #[must_use]
    pub fn render_slot(&self, index: usize, float: bool) -> Option<String> {
        match self.slots.get(index)? {
            DartPoolSlot::Immediate(raw) => Some(render_immediate(*raw, float)),
            DartPoolSlot::Object(reference) => {
                let mut path: BTreeSet<u32> = BTreeSet::new();
                let mut budget: usize = MAX_LITERAL_NODES;
                self.render_object(*reference, 0, &mut path, &mut budget)
            }
            DartPoolSlot::NativeFunction | DartPoolSlot::Unmodelled => None,
        }
    }

    fn object_kind(&self, reference: u32) -> DartPoolLiteralKind {
        let Some(object): Option<&DartPoolObject> = self.object(reference) else {
            return DartPoolLiteralKind::Unresolved;
        };
        match object.kind {
            DartPoolObjectKind::Text => DartPoolLiteralKind::Str,
            DartPoolObjectKind::Double => DartPoolLiteralKind::Double,
            DartPoolObjectKind::Mint => DartPoolLiteralKind::Integer,
            DartPoolObjectKind::List { .. } => DartPoolLiteralKind::List,
            DartPoolObjectKind::Class
            | DartPoolObjectKind::Function
            | DartPoolObjectKind::Field
            | DartPoolObjectKind::Library => DartPoolLiteralKind::Named,
            DartPoolObjectKind::Type
            | DartPoolObjectKind::TypeParameter
            | DartPoolObjectKind::RecordType => DartPoolLiteralKind::Type,
            DartPoolObjectKind::TypeArguments => DartPoolLiteralKind::TypeArguments,
            DartPoolObjectKind::Symbol => DartPoolLiteralKind::Symbol,
            DartPoolObjectKind::Opaque => DartPoolLiteralKind::Unresolved,
        }
    }

    fn object(&self, reference: u32) -> Option<&DartPoolObject> {
        self.objects.get(usize::try_from(reference).ok()?)
    }

    fn render_object(
        &self,
        reference: u32,
        depth: usize,
        path: &mut BTreeSet<u32>,
        budget: &mut usize,
    ) -> Option<String> {
        if depth > MAX_LITERAL_DEPTH || *budget == 0 || !path.insert(reference) {
            return None;
        }
        *budget -= 1;
        let rendered: Option<String> = self.render_visited(reference, depth, path, budget);
        path.remove(&reference);
        rendered
    }

    fn render_visited(
        &self,
        reference: u32,
        depth: usize,
        path: &mut BTreeSet<u32>,
        budget: &mut usize,
    ) -> Option<String> {
        let object: &DartPoolObject = self.object(reference)?;
        match object.kind {
            DartPoolObjectKind::Text => object
                .text
                .as_deref()
                .map(|text: &str| render_string(text, object.text_is_escaped)),
            DartPoolObjectKind::Mint => object.immediate.map(|value: i64| value.to_string()),
            DartPoolObjectKind::Double => object
                .immediate
                .map(|bits: i64| render_double(f64::from_bits(bits as u64))),
            DartPoolObjectKind::List { immutable } => {
                Some(self.render_list(object, immutable, depth, path, budget))
            }
            DartPoolObjectKind::Class => {
                self.declared_name(object, self.declarations.declarations.class.name_reference)
            }
            DartPoolObjectKind::Function => self.declared_name(
                object,
                self.declarations.declarations.function.name_reference,
            ),
            DartPoolObjectKind::Field => {
                self.declared_name(object, self.declarations.declarations.field.name_reference)
            }
            DartPoolObjectKind::Library => {
                self.declared_name(object, self.declarations.declarations.library.url_reference)
            }
            DartPoolObjectKind::Type => self.render_type(object, depth, path, budget),
            DartPoolObjectKind::TypeParameter | DartPoolObjectKind::RecordType => None,
            DartPoolObjectKind::TypeArguments => {
                self.render_type_arguments(object, depth, path, budget)
            }
            DartPoolObjectKind::Symbol => self.render_symbol(object),
            DartPoolObjectKind::Opaque => None,
        }
    }

    fn render_symbol(&self, object: &DartPoolObject) -> Option<String> {
        let name_reference: u32 = *object.references.first()?;
        let name: &DartPoolObject = self.object(name_reference)?;
        if name.kind != DartPoolObjectKind::Text {
            return None;
        }
        let text: &str = name.text.as_deref()?;
        if text.chars().count() > MAX_LITERAL_CHARS {
            return None;
        }
        Some(format!(
            "Symbol({})",
            render_string(text, name.text_is_escaped)
        ))
    }

    fn render_type(
        &self,
        object: &DartPoolObject,
        depth: usize,
        path: &mut BTreeSet<u32>,
        budget: &mut usize,
    ) -> Option<String> {
        let class_id: i32 = object.class_id?;
        let mut matched: bool = false;
        let mut declared: Option<String> = None;
        for candidate in &self.objects {
            if candidate.kind == DartPoolObjectKind::Class && candidate.class_id == Some(class_id) {
                if matched {
                    return None;
                }
                matched = true;
                declared = self.declared_name(
                    candidate,
                    self.declarations.declarations.class.name_reference,
                );
            }
        }
        let mut rendered: String = if matched {
            declared?
        } else {
            u16::try_from(class_id)
                .ok()
                .and_then(predefined_name)
                .map(str::to_owned)?
        };
        let arguments: u32 = *object.references.get(2)?;
        if !self.is_null_object(arguments) {
            let arguments_object: &DartPoolObject = self.object(arguments)?;
            if arguments_object.kind != DartPoolObjectKind::TypeArguments {
                return None;
            }
            rendered.push_str(&self.render_object(arguments, depth + 1, path, budget)?);
        }
        object.type_flags?;
        Some(rendered)
    }

    fn render_type_arguments(
        &self,
        object: &DartPoolObject,
        depth: usize,
        path: &mut BTreeSet<u32>,
        budget: &mut usize,
    ) -> Option<String> {
        let elements: &[u32] = object.references.get(1..)?;
        if elements.is_empty() {
            return None;
        }
        let shown: usize = elements.len().min(MAX_LIST_ELEMENTS);
        let mut rendered: Vec<String> = Vec::with_capacity(shown);
        for (position, element) in elements.iter().enumerate().take(shown) {
            let value: &DartPoolObject = self.object(*element)?;
            match value.kind {
                DartPoolObjectKind::Type => {
                    rendered.push(self.render_object(*element, depth + 1, path, budget)?);
                }
                DartPoolObjectKind::TypeParameter => {
                    rendered.push(format!("{TYPE_PARAMETER_PREFIX}{position}"));
                }
                DartPoolObjectKind::RecordType => {
                    rendered.push(String::from(RECORD_TYPE_TOKEN));
                }
                _ => return None,
            }
        }
        if elements.len() > shown {
            rendered.push(ELISION.to_owned());
        }
        Some(format!("<{}>", rendered.join(", ")))
    }

    fn is_null_object(&self, reference: u32) -> bool {
        if reference != NULL_OBJECT_REFERENCE {
            return false;
        }
        self.object(reference)
            .is_some_and(|object: &DartPoolObject| {
                object.kind == DartPoolObjectKind::Opaque
                    && object.text.is_none()
                    && !object.text_is_escaped
                    && object.immediate.is_none()
                    && object.references.is_empty()
                    && object.class_id.is_none()
                    && object.type_flags.is_none()
            })
    }

    fn declared_name(&self, object: &DartPoolObject, slot: usize) -> Option<String> {
        let reference: u32 = *object.references.get(slot)?;
        let named: &DartPoolObject = self.object(reference)?;
        if named.kind != DartPoolObjectKind::Text || named.text_is_escaped {
            return None;
        }
        named.text.clone()
    }

    fn render_list(
        &self,
        object: &DartPoolObject,
        immutable: bool,
        depth: usize,
        path: &mut BTreeSet<u32>,
        budget: &mut usize,
    ) -> String {
        let elements: &[u32] = object
            .references
            .get(..object.references.len().min(MAX_LIST_ELEMENTS))
            .unwrap_or(&[]);
        let mut rendered: Vec<String> = Vec::with_capacity(elements.len());
        for element in elements {
            rendered.push(
                self.render_object(*element, depth + 1, path, budget)
                    .unwrap_or_else(|| UNRESOLVED_TOKEN.to_owned()),
            );
        }
        if object.references.len() > elements.len() {
            rendered.push(ELISION.to_owned());
        }
        let prefix: &str = if immutable { "const [" } else { "[" };
        format!("{prefix}{}]", rendered.join(", "))
    }
}

pub const UNRESOLVED_TOKEN: &str = "?";

fn index_function_parameters(inventory: &DartPinnedInventory) -> BTreeMap<String, Option<u8>> {
    let mut index: BTreeMap<String, Option<u8>> = BTreeMap::new();
    for library in &inventory.libraries {
        for class in &library.classes {
            for method in &class.methods {
                let Some(name): Option<&str> = method.name.as_deref() else {
                    continue;
                };
                record_parameter_count(&mut index, name, method.parameter_count);
                if let Some(class_name) = class.name.as_deref() {
                    record_parameter_count(
                        &mut index,
                        &format!("{class_name}.{name}"),
                        method.parameter_count,
                    );
                }
            }
        }
    }
    index
}

fn record_parameter_count(
    index: &mut BTreeMap<String, Option<u8>>,
    name: &str,
    count: Option<usize>,
) {
    let candidate: Option<u8> = count.and_then(|value: usize| u8::try_from(value).ok());
    match index.entry(name.to_owned()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if *entry.get() != candidate {
                entry.insert(None);
            }
        }
    }
}

fn widest_pool(nodes: &[DartGraphNode]) -> Option<Vec<DartPoolSlot>> {
    nodes
        .iter()
        .filter(|node: &&DartGraphNode| !node.pool_slots.is_empty())
        .max_by_key(|node: &&DartGraphNode| node.pool_slots.len())
        .map(|node: &DartGraphNode| node.pool_slots.clone())
}

fn compact(node: &DartGraphNode, layout: DartPinnedLayout) -> DartPoolObject {
    DartPoolObject {
        kind: object_kind(node, layout),
        text: node.text.clone(),
        text_is_escaped: node.text_is_escaped,
        immediate: node.immediate,
        references: node.references.clone(),
        class_id: node.class_id,
        type_flags: node.type_flags,
    }
}

fn classify_symbol_objects(objects: &mut [DartPoolObject], layout: DartPinnedLayout) {
    let mut symbol_class_id: Option<i32> = None;
    for object in objects.iter() {
        if object.kind != DartPoolObjectKind::Class {
            continue;
        }
        let Some(name_reference): Option<u32> = object
            .references
            .get(layout.declarations.class.name_reference)
            .copied()
        else {
            continue;
        };
        if exact_text(objects, name_reference) != Some(SYMBOL_CLASS_NAME) {
            continue;
        }
        let Some(library_reference): Option<u32> = object
            .references
            .get(layout.declarations.class.library_reference)
            .copied()
        else {
            continue;
        };
        let Ok(library_index): core::result::Result<usize, _> = usize::try_from(library_reference)
        else {
            continue;
        };
        let Some(library): Option<&DartPoolObject> = objects.get(library_index) else {
            continue;
        };
        if library.kind != DartPoolObjectKind::Library {
            continue;
        }
        let Some(uri_reference): Option<u32> = library
            .references
            .get(layout.declarations.library.url_reference)
            .copied()
        else {
            continue;
        };
        if exact_text(objects, uri_reference) != Some(SYMBOL_LIBRARY_URI) {
            continue;
        }
        let Some(class_id): Option<i32> = object.class_id else {
            return;
        };
        if symbol_class_id.replace(class_id).is_some() {
            return;
        }
    }
    let Some(symbol_class_id): Option<i32> = symbol_class_id else {
        return;
    };
    for index in 0..objects.len() {
        let is_symbol: bool = {
            let object: &DartPoolObject = &objects[index];
            object.kind == DartPoolObjectKind::Opaque
                && object.class_id == Some(symbol_class_id)
                && object.references.len() == 1
                && object
                    .references
                    .first()
                    .and_then(|reference: &u32| objects.get(usize::try_from(*reference).ok()?))
                    .is_some_and(|name: &DartPoolObject| {
                        name.kind == DartPoolObjectKind::Text && name.text.is_some()
                    })
        };
        if is_symbol {
            objects[index].kind = DartPoolObjectKind::Symbol;
        }
    }
}

fn exact_text(objects: &[DartPoolObject], reference: u32) -> Option<&str> {
    let object: &DartPoolObject = objects.get(usize::try_from(reference).ok()?)?;
    if object.kind != DartPoolObjectKind::Text || object.text_is_escaped {
        return None;
    }
    object.text.as_deref()
}

fn object_kind(node: &DartGraphNode, layout: DartPinnedLayout) -> DartPoolObjectKind {
    match node.kind {
        DartGraphNodeKind::String => return DartPoolObjectKind::Text,
        DartGraphNodeKind::Class => return DartPoolObjectKind::Class,
        DartGraphNodeKind::Function => return DartPoolObjectKind::Function,
        DartGraphNodeKind::Field => return DartPoolObjectKind::Field,
        DartGraphNodeKind::Library => return DartPoolObjectKind::Library,
        DartGraphNodeKind::Type => return DartPoolObjectKind::Type,
        DartGraphNodeKind::TypeArguments => return DartPoolObjectKind::TypeArguments,
        DartGraphNodeKind::Unknown
        | DartGraphNodeKind::Other
        | DartGraphNodeKind::PatchClass
        | DartGraphNodeKind::FunctionType => {}
    }
    let Some(class_id): Option<i32> = node.class_id else {
        return DartPoolObjectKind::Opaque;
    };
    if class_id == MINT_CLASS_ID {
        return DartPoolObjectKind::Mint;
    }
    let Ok(cid): std::result::Result<u32, std::num::TryFromIntError> = u32::try_from(class_id)
    else {
        return DartPoolObjectKind::Opaque;
    };
    match layout.cluster_body_kind(cid) {
        Some(DartClusterBodyKind::TypeParameter) => DartPoolObjectKind::TypeParameter,
        Some(DartClusterBodyKind::RecordType) => DartPoolObjectKind::RecordType,
        Some(DartClusterBodyKind::Double) => DartPoolObjectKind::Double,
        Some(DartClusterBodyKind::Array) => DartPoolObjectKind::List {
            immutable: u16::try_from(cid)
                .ok()
                .and_then(predefined_name)
                .is_some_and(|name: &str| name == IMMUTABLE_ARRAY_NAME),
        },
        _ => DartPoolObjectKind::Opaque,
    }
}

fn render_immediate(raw: i64, float: bool) -> String {
    if float {
        return render_double(f64::from_bits(raw as u64));
    }
    if (-SMALL_INTEGER_BOUND..=SMALL_INTEGER_BOUND).contains(&raw) {
        return raw.to_string();
    }
    format!("{:#x}", raw as u64)
}

pub fn render_double(value: f64) -> String {
    if value.is_nan() {
        return "double.nan".to_owned();
    }
    if value.is_infinite() {
        let mut text: String = String::new();
        if value.is_sign_negative() {
            text.push('-');
        }
        text.push_str("double.infinity");
        return text;
    }
    let mut text: String = format!("{value}");
    if !text.contains('.') && !text.contains('e') && !text.contains('E') {
        text.push_str(".0");
    }
    text
}

fn quote_string(text: &str, already_escaped: bool) -> String {
    if already_escaped {
        format!("\"{text}\"")
    } else {
        format!("\"{}\"", escape_dart_string(text))
    }
}

fn trim_partial_escape(head: &str) -> &str {
    if let Some(open) = head.rfind("\\u{")
        && !head[open..].contains('}')
    {
        return &head[..open];
    }
    let trailing: usize = head.chars().rev().take_while(|c: &char| *c == '\\').count();
    if trailing % 2 == 1 {
        return &head[..head.len().saturating_sub(1)];
    }
    head
}

fn render_string(text: &str, already_escaped: bool) -> String {
    let total: usize = text.chars().count();
    if total <= MAX_LITERAL_CHARS {
        return quote_string(text, already_escaped);
    }
    let head: String = text.chars().take(MAX_LITERAL_CHARS).collect::<String>();
    let head: &str = if already_escaped {
        trim_partial_escape(&head)
    } else {
        head.as_str()
    };
    format!(
        "{TRUNCATED_STRING}({}, {total})",
        quote_string(head, already_escaped)
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn text_object(text: &str) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::Text,
            text: Some(text.to_owned()),
            text_is_escaped: false,
            immediate: None,
            references: Vec::new(),
            class_id: None,
            type_flags: None,
        }
    }

    fn list_object(references: Vec<u32>) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::List { immutable: false },
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
            class_id: None,
            type_flags: None,
        }
    }

    fn type_object(references: Vec<u32>, class_id: i32, type_flags: u64) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::Type,
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
            class_id: Some(class_id),
            type_flags: Some(type_flags),
        }
    }

    fn type_arguments_object(references: Vec<u32>) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::TypeArguments,
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
            class_id: None,
            type_flags: None,
        }
    }

    fn opaque_object(references: Vec<u32>, class_id: i32) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::Opaque,
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
            class_id: Some(class_id),
            type_flags: None,
        }
    }

    fn declaration_object(
        kind: DartPoolObjectKind,
        references: Vec<u32>,
        class_id: Option<i32>,
    ) -> DartPoolObject {
        DartPoolObject {
            kind,
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
            class_id,
            type_flags: None,
        }
    }

    fn table(slots: Vec<DartPoolSlot>, mut objects: Vec<DartPoolObject>) -> DartPoolTable {
        classify_symbol_objects(
            &mut objects,
            super::super::dart_graph_layout::DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
        );
        DartPoolTable {
            slots,
            objects,
            declarations: super::super::dart_graph_layout::DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
            function_parameters: BTreeMap::new(),
        }
    }

    fn symbol_objects(library_uri: &str, symbol_name: &str) -> Vec<DartPoolObject> {
        let mut library_references: Vec<u32> = vec![0; 10];
        library_references[1] = 2;
        let mut class_references: Vec<u32> = vec![0; 13];
        class_references[0] = 1;
        class_references[7] = 3;
        vec![
            text_object("unused"),
            text_object(SYMBOL_CLASS_NAME),
            text_object(library_uri),
            declaration_object(DartPoolObjectKind::Library, library_references, None),
            declaration_object(DartPoolObjectKind::Class, class_references, Some(402)),
            text_object(symbol_name),
            opaque_object(vec![5], 402),
        ]
    }

    #[test]
    fn parameter_counts_require_bounded_unambiguous_metadata() {
        let mut index: BTreeMap<String, Option<u8>> = BTreeMap::new();
        record_parameter_count(&mut index, "f", Some(1));
        record_parameter_count(&mut index, "f", Some(1));
        assert_eq!(index.get("f").copied().flatten(), Some(1));

        record_parameter_count(&mut index, "f", Some(2));
        assert_eq!(index.get("f").copied().flatten(), None);

        record_parameter_count(&mut index, "large", Some(usize::from(u8::MAX) + 1));
        record_parameter_count(&mut index, "missing", None);
        assert_eq!(index.get("large").copied().flatten(), None);
        assert_eq!(index.get("missing").copied().flatten(), None);
    }

    #[test]
    fn exact_internal_symbol_instance_renders_from_its_string_field() {
        let objects: Vec<DartPoolObject> = symbol_objects(SYMBOL_LIBRARY_URI, "shipment.status");
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(6)], objects);
        assert_eq!(
            pool.kind_at_offset(DART_POOL_ELEMENT_BASE_BYTES, false),
            DartPoolLiteralKind::Symbol
        );
        assert_eq!(
            pool.render_slot(0, false).as_deref(),
            Some("Symbol(\"shipment.status\")")
        );
    }

    #[test]
    fn symbol_classification_refuses_ambiguous_or_malformed_instances() {
        let public_pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(6)],
            symbol_objects("dart:core", "shipment.status"),
        );
        assert_eq!(public_pool.render_slot(0, false), None);

        let mut duplicate_objects: Vec<DartPoolObject> =
            symbol_objects(SYMBOL_LIBRARY_URI, "shipment.status");
        duplicate_objects.push(duplicate_objects[4].clone());
        let duplicate_pool: DartPoolTable = table(vec![DartPoolSlot::Object(6)], duplicate_objects);
        assert_eq!(duplicate_pool.render_slot(0, false), None);

        let mut extra_reference_objects: Vec<DartPoolObject> =
            symbol_objects(SYMBOL_LIBRARY_URI, "shipment.status");
        extra_reference_objects[6].references.push(5);
        let extra_reference_pool: DartPoolTable =
            table(vec![DartPoolSlot::Object(6)], extra_reference_objects);
        assert_eq!(extra_reference_pool.render_slot(0, false), None);

        let long_name: String = "s".repeat(MAX_LITERAL_CHARS + 1);
        let long_name_pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(6)],
            symbol_objects(SYMBOL_LIBRARY_URI, &long_name),
        );
        assert_eq!(long_name_pool.render_slot(0, false), None);
    }

    #[test]
    fn slot_index_rejects_offsets_outside_the_pool() {
        let pool: DartPoolTable = table(vec![DartPoolSlot::Immediate(1)], Vec::new());
        assert_eq!(pool.slot_index(DART_POOL_ELEMENT_BASE_BYTES), Some(0));
        assert_eq!(
            pool.slot_index(DART_POOL_ELEMENT_BASE_BYTES + 8),
            None,
            "a slot past the end of the pool must not resolve"
        );
        assert_eq!(pool.slot_index(0), None, "the pool header is not a slot");
        assert_eq!(
            pool.slot_index(DART_POOL_ELEMENT_BASE_BYTES + 4),
            None,
            "a misaligned pool offset is not a slot"
        );
        assert_eq!(pool.render_at_offset(u64::MAX, false), None);
    }

    #[test]
    fn cyclic_object_reference_terminates_with_the_placeholder() {
        let objects: Vec<DartPoolObject> = vec![
            text_object("unused"),
            list_object(vec![2]),
            list_object(vec![1]),
        ];
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(1)], objects);
        let rendered: String = pool.render_slot(0, false).expect("a list always renders");
        assert_eq!(
            rendered, "[[?]]",
            "a pool cycle must stop at the placeholder rather than recurse"
        );
    }

    #[test]
    fn cyclic_type_arguments_refuse_without_recursive_growth() {
        let objects: Vec<DartPoolObject> = vec![
            text_object("unused"),
            type_arguments_object(vec![0, 2]),
            type_object(vec![0, 0, 1], 40, 642),
        ];
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(1)], objects);
        assert_eq!(
            pool.kind_at_offset(DART_POOL_ELEMENT_BASE_BYTES, false),
            DartPoolLiteralKind::TypeArguments
        );
        assert_eq!(pool.render_slot(0, false), None);
        assert_eq!(pool.render_slot(0, false), None);
    }

    #[test]
    fn type_references_refuse_unrelated_object_kinds() {
        let objects: Vec<DartPoolObject> = vec![
            text_object("wrong"),
            text_object("not-null"),
            type_object(vec![0, 0, 0], 40, 641),
            type_arguments_object(vec![0, 0]),
        ];
        let pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(2), DartPoolSlot::Object(3)],
            objects,
        );
        assert_eq!(pool.render_slot(0, false), None);
        assert_eq!(pool.render_slot(1, false), None);
    }

    #[test]
    fn canonical_null_reference_renders_a_bare_type() {
        let objects: Vec<DartPoolObject> = vec![
            text_object("unused"),
            DartPoolObject {
                kind: DartPoolObjectKind::Opaque,
                text: None,
                text_is_escaped: false,
                immediate: None,
                references: Vec::new(),
                class_id: None,
                type_flags: None,
            },
            type_object(vec![0, 0, NULL_OBJECT_REFERENCE], 40, 641),
        ];
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(2)], objects);
        assert_eq!(pool.render_slot(0, false).as_deref(), Some("Error"));
    }

    #[test]
    fn deep_nesting_is_depth_bounded() {
        let mut objects: Vec<DartPoolObject> = vec![text_object("root")];
        for index in 1..24_u32 {
            objects.push(list_object(vec![index + 1]));
        }
        objects.push(text_object("leaf"));
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(1)], objects);
        let rendered: String = pool.render_slot(0, false).expect("a list always renders");
        assert!(
            rendered.matches('[').count() <= MAX_LITERAL_DEPTH + 1,
            "nesting must stop at the depth bound, got {rendered}"
        );
        assert!(rendered.ends_with(']'));
    }

    #[test]
    fn wide_list_is_element_bounded() {
        let mut objects: Vec<DartPoolObject> = vec![text_object("root")];
        let elements: Vec<u32> = (2..40_u32).collect::<Vec<u32>>();
        objects.push(list_object(elements));
        for index in 2..40_u32 {
            objects.push(text_object(&format!("e{index}")));
        }
        let pool: DartPoolTable = table(vec![DartPoolSlot::Object(1)], objects);
        let rendered: String = pool.render_slot(0, false).expect("a list always renders");
        assert_eq!(
            rendered.matches("\"e").count(),
            MAX_LIST_ELEMENTS,
            "a wide pool array must render a bounded prefix, got {rendered}"
        );
        assert!(rendered.contains(ELISION));
    }

    #[test]
    fn long_string_is_size_bounded() {
        let long: String = "a".repeat(MAX_LITERAL_CHARS * 4);
        let pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(1)],
            vec![text_object("unused"), text_object(&long)],
        );
        let rendered: String = pool.render_slot(0, false).expect("string renders");
        assert!(rendered.len() < long.len());
        assert!(
            rendered.starts_with(&format!("{TRUNCATED_STRING}(\"")),
            "a truncated string must not be renderable as a complete literal, got {rendered}"
        );
        assert!(
            rendered.ends_with(&format!(", {})", long.chars().count())),
            "a truncated string must carry the character count it was cut from, got {rendered}"
        );
        let complete: DartPoolTable = table(
            vec![DartPoolSlot::Object(1)],
            vec![text_object("unused"), text_object("a")],
        );
        let intact: String = complete.render_slot(0, false).expect("string renders");
        assert_eq!(
            intact, "\"a\"",
            "a complete string must stay a plain literal so the two cases cannot be confused"
        );
    }

    #[test]
    fn a_truncated_escaped_string_never_ends_inside_an_escape_sequence() {
        let escaped: String = "\\u{0041}X".repeat(MAX_LITERAL_CHARS);
        const {
            assert!(
                MAX_LITERAL_CHARS % 9 != 0,
                "the unit length must not divide the cut, or the trim is never exercised"
            );
        }
        let mut object: DartPoolObject = text_object(&escaped);
        object.text_is_escaped = true;
        let pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(1)],
            vec![text_object("unused"), object],
        );
        let rendered: String = pool.render_slot(0, false).expect("string renders");
        let opens: usize = rendered.matches("\\u{").count();
        let closes: usize = rendered.matches('}').count();
        assert_eq!(
            opens, closes,
            "every escape the renderer emits must be closed, got {rendered}"
        );
    }

    #[test]
    fn immediate_renders_as_double_only_for_a_float_load() {
        let bits: i64 = 19.95_f64.to_bits() as i64;
        let pool: DartPoolTable = table(vec![DartPoolSlot::Immediate(bits)], Vec::new());
        assert_eq!(pool.render_slot(0, true).as_deref(), Some("19.95"));
        assert_eq!(
            pool.render_slot(0, false).as_deref(),
            Some("0x4033f33333333333"),
            "an integer load of the same slot must not be typed as a double"
        );
    }

    #[test]
    fn whole_doubles_keep_a_dart_fraction() {
        assert_eq!(render_double(2400.0), "2400.0");
        assert_eq!(render_double(19.95), "19.95");
        assert_eq!(render_double(-0.5), "-0.5");
    }

    #[test]
    fn non_finite_doubles_render_as_named_dart_constants() {
        assert_eq!(render_double(f64::NAN), "double.nan");
        assert_eq!(render_double(f64::INFINITY), "double.infinity");
        assert_eq!(render_double(f64::NEG_INFINITY), "-double.infinity");
    }

    #[test]
    fn native_function_and_unmodelled_slots_do_not_render() {
        let pool: DartPoolTable = table(
            vec![DartPoolSlot::NativeFunction, DartPoolSlot::Unmodelled],
            Vec::new(),
        );
        assert_eq!(pool.render_slot(0, false), None);
        assert_eq!(pool.render_slot(1, false), None);
        assert_eq!(
            pool.kind_at_offset(DART_POOL_ELEMENT_BASE_BYTES, false),
            DartPoolLiteralKind::NativeFunction
        );
    }

    #[test]
    fn escaped_two_byte_text_is_quoted_without_double_escaping() {
        let mut object: DartPoolObject = text_object("bad\\uD83D");
        object.text_is_escaped = true;
        let pool: DartPoolTable = table(
            vec![DartPoolSlot::Object(1)],
            vec![text_object("unused"), object],
        );
        assert_eq!(
            pool.render_slot(0, false).as_deref(),
            Some("\"bad\\uD83D\""),
            "an unpaired surrogate renders as its deterministic escape"
        );
    }
}
