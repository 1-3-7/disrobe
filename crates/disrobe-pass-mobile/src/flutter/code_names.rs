use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::code_table::{DartCodeTable, DartCodeTableEntry};
use super::dart_graph::{DartGraphNode, DartGraphNodeKind};
use super::dart_graph_layout::{
    DartClassBodyLayout, DartDeclarationBodyLayouts, DartFunctionBodyLayout, DartPinnedLayout,
};

const TOP_LEVEL_CLASS_NAME: &str = "::";

const OPTIMIZED_OUT: &str = "<optimized out>";

const FUTURE_IMPLEMENTATION_CLASS: &str = "_Future";

const FUTURE_CLASS: &str = "Future";

const ASYNC_LIBRARY_URL: &str = "dart:async";

const CLOSURE_DATA_CLASS: &str = "ClosureData";

const CLOSURE_FUNCTION_KIND: u32 = 1;

const CONSTRUCTOR_KIND: u32 = 5;

const MAX_CLOSURE_NESTING: usize = 64;

const TYPED_DATA_ELEMENTS: [&str; 14] = [
    "Int8",
    "Uint8",
    "Uint8Clamped",
    "Int16",
    "Uint16",
    "Int32",
    "Uint32",
    "Int64",
    "Uint64",
    "Int32x4",
    "Float32x4",
    "Float64x2",
    "Float32",
    "Float64",
];

const SELF_NAMED_CLASSES: [&str; 45] = [
    "Float32x4",
    "Float64x2",
    "Int32x4",
    "Pointer",
    "DynamicLibrary",
    "Null",
    "Never",
    "Class",
    "TypeParameters",
    "TypeArguments",
    "PatchClass",
    "Function",
    "ClosureData",
    "FfiTrampolineData",
    "Field",
    "Script",
    "Library",
    "LibraryPrefix",
    "Namespace",
    "KernelProgramInfo",
    "WeakSerializationReference",
    "WeakArray",
    "Code",
    "Bytecode",
    "Instructions",
    "InstructionsSection",
    "InstructionsTable",
    "ObjectPool",
    "CodeSourceMap",
    "PcDescriptors",
    "CompressedStackMaps",
    "LocalVarDescriptors",
    "ExceptionHandlers",
    "Context",
    "ContextScope",
    "Sentinel",
    "SingleTargetCache",
    "ICData",
    "MegamorphicCache",
    "SubtypeTestCache",
    "LoadingUnit",
    "ApiError",
    "LanguageError",
    "UnhandledException",
    "UnwindError",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartCodeNameRole {
    CodeOwner,
    AllocationStub,
    SharedCode,
    DroppedOwner,
    DiscardedCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartCodeName {
    pub instructions_offset: u64,
    pub code_index: u64,
    pub role: DartCodeNameRole,
    pub qualified_name: String,
    pub member_name: String,
    pub class_name: Option<String>,
    pub library_url: Option<String>,
}

struct DartCodeNamer<'graph> {
    nodes: &'graph [DartGraphNode],
    layout: DartPinnedLayout,
    closure_data_class_id: Option<i32>,
    classes_by_id: BTreeMap<i32, Option<usize>>,
}

pub(super) fn code_names(
    nodes: &[DartGraphNode],
    layout: &DartPinnedLayout,
    table: &DartCodeTable,
) -> Vec<DartCodeName> {
    let mut classes_by_id: BTreeMap<i32, Option<usize>> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        if node.kind != DartGraphNodeKind::Class {
            continue;
        }
        if let Some(class_id) = node.class_id {
            classes_by_id
                .entry(class_id)
                .and_modify(|seen: &mut Option<usize>| *seen = None)
                .or_insert(Some(index));
        }
    }
    let namer: DartCodeNamer<'_> = DartCodeNamer {
        nodes,
        layout: *layout,
        closure_data_class_id: layout
            .class_id(CLOSURE_DATA_CLASS)
            .and_then(|cid: u32| i32::try_from(cid).ok()),
        classes_by_id,
    };
    let owner_reference: usize = layout.declarations.code.owner_reference;
    let mut owners: BTreeMap<usize, u32> = BTreeMap::new();
    for node in nodes {
        let Some(ordinal) = node.code_ordinal else {
            continue;
        };
        let Some(entry) = table.first_entry_with_code.checked_add(ordinal) else {
            continue;
        };
        if entry >= table.len() {
            continue;
        }
        if let Some(owner) = node.references.get(owner_reference) {
            owners.insert(entry, *owner);
        }
    }
    let mut entries: Vec<DartCodeName> = Vec::new();
    for (entry, owner) in &owners {
        if namer.function(*owner).is_some() {
            namer.push(
                &mut entries,
                table,
                *entry,
                *owner,
                DartCodeNameRole::CodeOwner,
            );
        } else if let Some(class) = namer.class(*owner) {
            namer.push_allocation_stub(&mut entries, table, *entry, class);
        }
    }
    for (index, node) in nodes.iter().enumerate() {
        if node.kind != DartGraphNodeKind::Function {
            continue;
        }
        let Some(entry) = node
            .code_index
            .and_then(|code_index: u64| usize::try_from(code_index).ok())
            .and_then(|code_index: usize| code_index.checked_sub(1))
            .filter(|entry: &usize| *entry < table.len())
        else {
            continue;
        };
        let Ok(reference) = u32::try_from(index) else {
            continue;
        };
        let role: DartCodeNameRole = match owners.get(&entry) {
            Some(owner) if *owner == reference => continue,
            Some(owner) if namer.function(*owner).is_some() => DartCodeNameRole::SharedCode,
            Some(_) => DartCodeNameRole::DroppedOwner,
            None if entry < table.first_entry_with_code => DartCodeNameRole::DiscardedCode,
            None => continue,
        };
        namer.push(&mut entries, table, entry, reference, role);
    }
    entries.sort_by(|left: &DartCodeName, right: &DartCodeName| {
        left.instructions_offset
            .cmp(&right.instructions_offset)
            .then_with(|| left.role.cmp(&right.role))
            .then_with(|| left.qualified_name.cmp(&right.qualified_name))
    });
    entries.dedup_by(|left: &mut DartCodeName, right: &mut DartCodeName| {
        left.instructions_offset == right.instructions_offset
            && left.qualified_name == right.qualified_name
    });
    entries
}

impl DartCodeNamer<'_> {
    const fn declarations(&self) -> DartDeclarationBodyLayouts {
        self.layout.declarations
    }

    fn node(&self, reference: u32) -> Option<&DartGraphNode> {
        self.nodes.get(usize::try_from(reference).ok()?)
    }

    fn function(&self, reference: u32) -> Option<&DartGraphNode> {
        self.node(reference)
            .filter(|node: &&DartGraphNode| node.kind == DartGraphNodeKind::Function)
    }

    fn class(&self, reference: u32) -> Option<&DartGraphNode> {
        self.node(reference)
            .filter(|node: &&DartGraphNode| node.kind == DartGraphNodeKind::Class)
    }

    fn text(&self, reference: u32) -> Option<&str> {
        let node: &DartGraphNode = self.node(reference)?;
        if node.kind != DartGraphNodeKind::String || node.text_is_escaped {
            return None;
        }
        node.text.as_deref()
    }

    fn push(
        &self,
        entries: &mut Vec<DartCodeName>,
        table: &DartCodeTable,
        entry: usize,
        function: u32,
        role: DartCodeNameRole,
    ) {
        let Some(instructions_offset) = table
            .entries
            .get(entry)
            .map(|value: &DartCodeTableEntry| value.instructions_offset)
        else {
            return;
        };
        let Some(qualified_name) = self.qualified_name(function, 0) else {
            return;
        };
        let Some(node) = self.function(function) else {
            return;
        };
        let Some(member_name) = self.member_name(node) else {
            return;
        };
        let owner: Option<&DartGraphNode> = self.owner_class(node);
        let class_name: Option<String> = owner
            .and_then(|class: &DartGraphNode| self.class_name(class))
            .map(|name: &str| scrub_name(name, false))
            .filter(|name: &String| !name.is_empty());
        let library_url: Option<String> = owner
            .and_then(|class: &DartGraphNode| self.library_url(class))
            .map(str::to_owned);
        entries.push(DartCodeName {
            instructions_offset,
            code_index: u64::try_from(entry).map_or(u64::MAX, |value: u64| value.saturating_add(1)),
            role,
            qualified_name,
            member_name,
            class_name,
            library_url,
        });
    }

    fn push_allocation_stub(
        &self,
        entries: &mut Vec<DartCodeName>,
        table: &DartCodeTable,
        entry: usize,
        class: &DartGraphNode,
    ) {
        let Some(instructions_offset) = table
            .entries
            .get(entry)
            .map(|value: &DartCodeTableEntry| value.instructions_offset)
        else {
            return;
        };
        let Some(visible) = self.user_visible_class_name(class) else {
            return;
        };
        let Some(scrubbed) = self
            .class_name(class)
            .map(|name: &str| scrub_name(name, false))
        else {
            return;
        };
        entries.push(DartCodeName {
            instructions_offset,
            code_index: u64::try_from(entry).map_or(u64::MAX, |value: u64| value.saturating_add(1)),
            role: DartCodeNameRole::AllocationStub,
            qualified_name: format!("new {visible}"),
            member_name: visible,
            class_name: Some(scrubbed),
            library_url: self.library_url(class).map(str::to_owned),
        });
    }

    fn kind(&self, function: &DartGraphNode) -> Option<u32> {
        let bits: u32 = self.declarations().function.kind_bits;
        function
            .state_bits
            .map(|tag: u32| tag & ((1_u32 << bits) - 1))
    }

    fn is_extension(&self, function: &DartGraphNode) -> bool {
        let layout: DartFunctionBodyLayout = self.declarations().function;
        function.state_bits.is_some_and(|tag: u32| {
            (tag >> layout.extension_member_bit) & 1 == 1
                || (tag >> layout.extension_type_member_bit) & 1 == 1
        })
    }

    fn member_name(&self, function: &DartGraphNode) -> Option<String> {
        let name: &str = self.text(
            *function
                .references
                .get(self.declarations().function.name_reference)?,
        )?;
        Some(scrub_name(name, self.is_extension(function)))
    }

    fn qualified_name(&self, function: u32, depth: usize) -> Option<String> {
        let node: &DartGraphNode = self.function(function)?;
        let member: String = self.member_name(node)?;
        let kind: u32 = self.kind(node)?;
        if kind == CLOSURE_FUNCTION_KIND {
            if depth >= MAX_CLOSURE_NESTING {
                return None;
            }
            let parent: String = match self.closure_parent(node) {
                Some(parent) => self.qualified_name(parent, depth + 1)?,
                None => OPTIMIZED_OUT.to_owned(),
            };
            return Some(format!("{parent}.{member}"));
        }
        if kind == CONSTRUCTOR_KIND {
            return Some(format!("new {member}"));
        }
        let class: &DartGraphNode = self.owner_class(node)?;
        if self.class_name(class)? == TOP_LEVEL_CLASS_NAME {
            return Some(member);
        }
        let mixin: &DartGraphNode = self.mixin(class);
        Some(format!("{}.{member}", self.user_visible_class_name(mixin)?))
    }

    fn closure_parent(&self, function: &DartGraphNode) -> Option<u32> {
        let layouts: DartDeclarationBodyLayouts = self.declarations();
        let data: &DartGraphNode =
            self.node(*function.references.get(layouts.function.data_reference)?)?;
        if data.class_id.is_none() || data.class_id != self.closure_data_class_id {
            return None;
        }
        let parent: u32 = *data
            .references
            .get(layouts.closure_data.parent_function_reference)?;
        self.function(parent).map(|_: &DartGraphNode| parent)
    }

    fn owner_class(&self, function: &DartGraphNode) -> Option<&DartGraphNode> {
        let layouts: DartDeclarationBodyLayouts = self.declarations();
        let owner: &DartGraphNode =
            self.node(*function.references.get(layouts.function.owner_reference)?)?;
        match owner.kind {
            DartGraphNodeKind::Class => Some(owner),
            DartGraphNodeKind::PatchClass => self
                .node(
                    *owner
                        .references
                        .get(layouts.patch_class.wrapped_class_reference)?,
                )
                .filter(|class: &&DartGraphNode| class.kind == DartGraphNodeKind::Class),
            _ => None,
        }
    }

    fn class_name(&self, class: &DartGraphNode) -> Option<&str> {
        self.text(
            *class
                .references
                .get(self.declarations().class.name_reference)?,
        )
    }

    fn library_url(&self, class: &DartGraphNode) -> Option<&str> {
        let layouts: DartDeclarationBodyLayouts = self.declarations();
        let library: &DartGraphNode =
            self.node(*class.references.get(layouts.class.library_reference)?)?;
        if library.kind != DartGraphNodeKind::Library {
            return None;
        }
        self.text(*library.references.get(layouts.library.url_reference)?)
    }

    fn mixin<'node>(&'node self, class: &'node DartGraphNode) -> &'node DartGraphNode {
        self.mixed_in_class(class).unwrap_or(class)
    }

    fn mixed_in_class(&self, class: &DartGraphNode) -> Option<&DartGraphNode> {
        let layout: DartClassBodyLayout = self.declarations().class;
        let state: u32 = class.state_bits?;
        if (state >> layout.transformed_mixin_application_bit) & 1 == 0 {
            return None;
        }
        let interfaces: &DartGraphNode =
            self.node(*class.references.get(layout.interfaces_reference)?)?;
        let mixin_type: &DartGraphNode = self.node(*interfaces.references.last()?)?;
        if mixin_type.kind != DartGraphNodeKind::Type {
            return None;
        }
        let class_id: i32 = mixin_type.class_id?;
        let index: usize = (*self.classes_by_id.get(&class_id)?)?;
        self.nodes.get(index)
    }

    fn user_visible_class_name(&self, class: &DartGraphNode) -> Option<String> {
        if let Some(predefined) = class
            .class_id
            .and_then(|cid: i32| u16::try_from(cid).ok())
            .filter(|cid: &u16| *cid < self.layout.class_ids.predefined_count())
            .and_then(|cid: u16| self.layout.class_ids.name(cid))
            .and_then(predefined_user_visible_name)
        {
            return Some(predefined);
        }
        let scrubbed: String = scrub_name(self.class_name(class)?, false);
        if scrubbed == FUTURE_IMPLEMENTATION_CLASS
            && self.library_url(class) == Some(ASYNC_LIBRARY_URL)
        {
            return Some(FUTURE_CLASS.to_owned());
        }
        Some(scrubbed)
    }
}

fn predefined_user_visible_name(cid_name: &str) -> Option<String> {
    let visible: &str = match cid_name {
        "Integer" | "Smi" | "Mint" => "int",
        "Double" => "double",
        "OneByteString" | "TwoByteString" | "ExternalOneByteString" | "ExternalTwoByteString" => {
            "String"
        }
        "Array" | "ImmutableArray" | "GrowableObjectArray" => "List",
        "Dynamic" => "dynamic",
        "Void" => "void",
        other => {
            if SELF_NAMED_CLASSES.contains(&other) {
                other
            } else {
                let element: &str = other
                    .strip_prefix("ExternalTypedData")
                    .or_else(|| other.strip_prefix("TypedData"))?
                    .strip_suffix("Array")?;
                return TYPED_DATA_ELEMENTS
                    .contains(&element)
                    .then(|| format!("{element}List"));
            }
        }
    };
    Some(visible.to_owned())
}

#[must_use]
pub fn scrub_name(name: &str, is_extension: bool) -> String {
    if name == TOP_LEVEL_CLASS_NAME {
        return String::new();
    }
    let unmangled: String = remove_private_keys(name, is_extension);
    let mut printer: String = String::new();
    let mut rest: &str = &unmangled;
    let mut is_setter: bool = false;
    if is_extension {
        let bytes: &[u8] = rest.as_bytes();
        let mut start: usize = 0;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'.' {
                printer.push_str(rest.get(start..=index).unwrap_or_default());
                rest = rest.get(index + 1..).unwrap_or_default();
                break;
            }
            if *byte == b':' {
                if start != 0 {
                    is_setter = false;
                    break;
                }
                if bytes.first() == Some(&b's') {
                    is_setter = true;
                }
                start = index + 1;
            }
        }
    }
    let bytes: &[u8] = rest.as_bytes();
    let mut start: usize = 0;
    let mut dot: Option<usize> = None;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b':' || (is_extension && *byte == b'#') {
            if start != 0 {
                start = 0;
                dot = None;
                break;
            }
            if bytes.first() == Some(&b's') {
                is_setter = true;
            }
            start = index + 1;
        } else if *byte == b'.' {
            if dot.is_some() {
                start = 0;
                dot = None;
                break;
            }
            dot = Some(index);
        }
    }
    if !is_extension && start == 0 && dot.is_none() {
        return unmangled;
    }
    let end: usize = match dot {
        Some(position) if position + 1 == bytes.len() => position,
        _ => bytes.len(),
    };
    printer.push_str(rest.get(start..end).unwrap_or_default());
    if is_setter {
        printer.push('=');
    }
    printer
}

fn remove_private_keys(name: &str, is_extension: bool) -> String {
    let bytes: &[u8] = name.as_bytes();
    let mut printer: String = String::with_capacity(name.len());
    let mut segment: usize = 0;
    let mut index: usize = 0;
    while index < bytes.len() {
        let byte: u8 = bytes[index];
        if byte == b'@' && bytes.get(index + 1).is_some_and(u8::is_ascii_digit) {
            printer.push_str(name.get(segment..index).unwrap_or_default());
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            segment = index;
            continue;
        }
        if is_extension && byte == b'|' {
            printer.push_str(name.get(segment..index).unwrap_or_default());
            printer.push('.');
            segment = index + 1;
        }
        index += 1;
    }
    if segment == 0 {
        return name.to_owned();
    }
    printer.push_str(name.get(segment..).unwrap_or_default());
    printer
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{predefined_user_visible_name, scrub_name};

    #[test]
    fn scrubbing_follows_the_sdk_for_every_internal_name_shape() {
        let cases: [(&str, bool, &str); 14] = [
            ("::", false, ""),
            ("computeChecksum", false, "computeChecksum"),
            ("_setClampedRange@8027147", false, "_setClampedRange"),
            ("get:result", false, "result"),
            ("set:_state@4048458", false, "_state="),
            ("init:_printClosure", false, "_printClosure"),
            ("dyn:[]", false, "[]"),
            ("ReceiptValidator.", false, "ReceiptValidator"),
            (
                "_ByteBuffer@8027147._New@8027147",
                false,
                "_ByteBuffer._New",
            ),
            ("a.b.c", false, "a.b.c"),
            ("get:set:x", false, "get:set:x"),
            ("Ledger|total", true, "Ledger.total"),
            ("Ledger|get#balance", true, "Ledger.balance"),
            ("Ledger|set#balance", true, "Ledger.balance="),
        ];
        for (internal, extension, expected) in cases {
            assert_eq!(
                scrub_name(internal, extension),
                expected,
                "scrubbing {internal}"
            );
        }
    }

    #[test]
    fn predefined_classes_take_the_names_the_sdk_prints() {
        assert_eq!(
            predefined_user_visible_name("GrowableObjectArray").as_deref(),
            Some("List")
        );
        assert_eq!(
            predefined_user_visible_name("ExternalTypedDataUint8ClampedArray").as_deref(),
            Some("Uint8ClampedList")
        );
        assert_eq!(
            predefined_user_visible_name("TypedDataFloat64x2Array").as_deref(),
            Some("Float64x2List")
        );
        assert_eq!(
            predefined_user_visible_name("TypedDataUint8ArrayView"),
            None
        );
        assert_eq!(predefined_user_visible_name("ByteBuffer"), None);
        assert_eq!(
            predefined_user_visible_name("Dynamic").as_deref(),
            Some("dynamic")
        );
    }
}
