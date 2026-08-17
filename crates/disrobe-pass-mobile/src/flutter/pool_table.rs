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

const NULL_OBJECT_REFERENCE: u32 = 1;

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
        let objects: Vec<DartPoolObject> = nodes
            .iter()
            .map(|node: &DartGraphNode| compact(node, layout))
            .collect::<Vec<DartPoolObject>>();
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
            DartPoolObjectKind::Type => DartPoolLiteralKind::Type,
            DartPoolObjectKind::TypeArguments => DartPoolLiteralKind::TypeArguments,
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
            DartPoolObjectKind::TypeArguments => {
                self.render_type_arguments(object, depth, path, budget)
            }
            DartPoolObjectKind::Opaque => None,
        }
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
        match object.type_flags? & 0x3 {
            0 => rendered.push('?'),
            1 => {}
            2 => rendered.push('*'),
            _ => return None,
        }
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
        let capacity: usize = elements.len().min(*budget);
        let mut rendered: Vec<String> = Vec::with_capacity(capacity);
        for element in elements {
            let value: &DartPoolObject = self.object(*element)?;
            if value.kind != DartPoolObjectKind::Type {
                return None;
            }
            rendered.push(self.render_object(*element, depth + 1, path, budget)?);
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

fn render_string(text: &str, already_escaped: bool) -> String {
    let bounded: String = if text.chars().count() > MAX_LITERAL_CHARS {
        let head: String = text.chars().take(MAX_LITERAL_CHARS).collect::<String>();
        format!("{head}{ELISION}")
    } else {
        text.to_owned()
    };
    if already_escaped {
        return format!("\"{bounded}\"");
    }
    format!("\"{}\"", escape_dart_string(&bounded))
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

    fn table(slots: Vec<DartPoolSlot>, objects: Vec<DartPoolObject>) -> DartPoolTable {
        DartPoolTable {
            slots,
            objects,
            declarations: super::super::dart_graph_layout::DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
            function_parameters: BTreeMap::new(),
        }
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
        assert!(rendered.ends_with(&format!("{ELISION}\"")));
        assert!(rendered.len() < long.len());
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
