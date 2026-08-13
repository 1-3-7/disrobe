use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::aot_lift::escape_dart_string;
use super::cid_table::predefined_name;
use super::dart_graph::{
    DartGraphLimits, DartGraphNode, DartGraphNodeKind, DartParsedGraph, DartPoolSlot,
};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartPoolLiteralKind {
    Str,
    Double,
    Integer,
    List,
    Named,
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
    Opaque,
}

#[derive(Debug, Clone)]
struct DartPoolObject {
    kind: DartPoolObjectKind,
    text: Option<String>,
    text_is_escaped: bool,
    immediate: Option<i64>,
    references: Vec<u32>,
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
        let DartPinnedGraph { graph, layout }: DartPinnedGraph = pinned;
        let DartParsedGraph { nodes, .. }: DartParsedGraph = graph;
        let Some(slots): Option<Vec<DartPoolSlot>> = widest_pool(&nodes) else {
            return Ok(None);
        };
        let objects: Vec<DartPoolObject> = nodes
            .iter()
            .map(|node: &DartGraphNode| compact(node, layout))
            .collect::<Vec<DartPoolObject>>();
        Ok(Some(Self {
            slots,
            objects,
            declarations: layout,
        }))
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
            DartPoolObjectKind::Opaque => None,
        }
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
    }
}

fn object_kind(node: &DartGraphNode, layout: DartPinnedLayout) -> DartPoolObjectKind {
    match node.kind {
        DartGraphNodeKind::String => return DartPoolObjectKind::Text,
        DartGraphNodeKind::Class => return DartPoolObjectKind::Class,
        DartGraphNodeKind::Function => return DartPoolObjectKind::Function,
        DartGraphNodeKind::Field => return DartPoolObjectKind::Field,
        DartGraphNodeKind::Library => return DartPoolObjectKind::Library,
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
        }
    }

    fn list_object(references: Vec<u32>) -> DartPoolObject {
        DartPoolObject {
            kind: DartPoolObjectKind::List { immutable: false },
            text: None,
            text_is_escaped: false,
            immediate: None,
            references,
        }
    }

    fn table(slots: Vec<DartPoolSlot>, objects: Vec<DartPoolObject>) -> DartPoolTable {
        DartPoolTable {
            slots,
            objects,
            declarations: super::super::dart_graph_layout::DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
        }
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
