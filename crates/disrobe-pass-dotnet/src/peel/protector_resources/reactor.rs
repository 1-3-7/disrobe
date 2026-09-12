use std::collections::{BTreeMap, BTreeSet};

use disrobe_cfg::{Flow, FlowGraph};

use crate::cil::{
    FlowControl, Instruction, MethodBody, OperandValue, SlotOp, method_body_code_size,
    method_body_extent, parse_method_body, slot_index_of,
};
use crate::metadata::{MetadataRoot, StreamHeader, parse_metadata_root, parse_table_stream};
use crate::model::{MethodModel, Resolver, TypeModel};
use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use crate::peel::deflatten::blocks::{absolute_target, int_literal};
use crate::signature::{
    TypeSig, TypeSigOrVoid, parse_field_sig_strict, parse_local_sig_strict,
    parse_method_sig_strict, parse_method_spec_sig_strict,
};
use crate::tables::{FieldRow, FieldRvaRow, ManifestResourceRow, RowRef, TableId};

use super::{
    ImageView, MAX_EMBEDDED_RESOURCES, MAX_RESOURCE_BYTES, ResourceStringRecovery,
    embedded_resource_bytes, first_resource, load_image, read_unicode_records_int32_strict,
    string_at,
};

#[must_use]
pub(super) fn recover(image: &[u8]) -> Option<ResourceStringRecovery> {
    if let Err(reason) = reactor_preflight(image)? {
        return Some(reactor_unknown_without_view(reason));
    }
    let view: ImageView = load_image(image).ok()?;
    match discover_reactor_static_candidate(image, &view) {
        Ok(Some(candidate)) => Some(recover_reactor_candidate(image, &view, candidate)),
        Ok(None) => Some(reactor_unknown(
            &view,
            "Unknown: Reactor managed methods contain no proven static string entry".to_string(),
        )),
        Err(reason) => Some(reactor_unknown(&view, reason)),
    }
}

fn reactor_preflight(image: &[u8]) -> Option<std::result::Result<(), String>> {
    let pe: PeImage = parse(image).ok()?;
    if pe.sections.len() > MAX_REACTOR_PE_SECTIONS {
        return Some(Err(
            "Unknown: Reactor PE section count exceeds the loader limit".to_string(),
        ));
    }
    let clr_directory = pe.clr_directory()?;
    let Ok(clr_size): std::result::Result<usize, std::num::TryFromIntError> =
        usize::try_from(clr_directory.size.max(72))
    else {
        return Some(Err(
            "Unknown: Reactor CLR directory size is not addressable".to_string(),
        ));
    };
    if clr_directory.rva == 0
        || exact_file_backed_rva_offset(image, &pe, clr_directory.rva, clr_size).is_none()
    {
        return Some(Err(
            "Unknown: Reactor CLR header is not uniquely file-backed".to_string(),
        ));
    }
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    Some(reactor_preflight_managed(image, &pe, &clr))
}

fn reactor_preflight_managed(
    image: &[u8],
    pe: &PeImage,
    clr: &ClrHeader,
) -> std::result::Result<(), String> {
    let metadata_size: usize = usize::try_from(clr.metadata.size)
        .map_err(|_| "Unknown: Reactor metadata size is not addressable".to_string())?;
    if clr.metadata.rva == 0 || metadata_size == 0 || metadata_size > MAX_REACTOR_METADATA_BYTES {
        return Err(
            "Unknown: Reactor metadata directory is outside the selected bounds".to_string(),
        );
    }
    let metadata_offset: usize =
        exact_file_backed_rva_offset(image, pe, clr.metadata.rva, metadata_size)
            .ok_or_else(|| "Unknown: Reactor metadata is not uniquely file-backed".to_string())?;
    let metadata_end: usize = metadata_offset
        .checked_add(metadata_size)
        .ok_or_else(|| "Unknown: Reactor metadata file range overflowed".to_string())?;
    let metadata: &[u8] = image
        .get(metadata_offset..metadata_end)
        .ok_or_else(|| "Unknown: Reactor metadata file range is truncated".to_string())?;
    let resources_size: usize = usize::try_from(clr.resources.size)
        .map_err(|_| "Unknown: Reactor resources size is not addressable".to_string())?;
    if resources_size > MAX_RESOURCE_BYTES
        || (resources_size != 0
            && (clr.resources.rva == 0
                || exact_file_backed_rva_offset(image, pe, clr.resources.rva, resources_size)
                    .is_none()))
    {
        return Err("Unknown: Reactor resources are outside the selected bounds".to_string());
    }
    let root: MetadataRoot = parse_metadata_root(image, pe, clr)
        .map_err(|error| format!("Unknown: Reactor metadata root is invalid: {error}"))?;
    if root.streams.len() > MAX_REACTOR_METADATA_STREAMS {
        return Err(
            "Unknown: Reactor metadata stream count exceeds the selected bound".to_string(),
        );
    }
    let mut selected_heap_bytes: usize = 0;
    for name in ["#Strings", "#Blob", "#US"] {
        if let Some(header) = root.streams.get(name) {
            let size: usize = usize::try_from(header.size)
                .map_err(|_| "Unknown: Reactor heap size is not addressable".to_string())?;
            if size > MAX_REACTOR_HEAP_BYTES {
                return Err("Unknown: Reactor metadata heap exceeds the byte cap".to_string());
            }
            let offset: usize = usize::try_from(header.offset)
                .map_err(|_| "Unknown: Reactor heap offset is not addressable".to_string())?;
            let end: usize = offset
                .checked_add(size)
                .ok_or_else(|| "Unknown: Reactor heap range overflowed".to_string())?;
            let heap: &[u8] = metadata
                .get(offset..end)
                .ok_or_else(|| "Unknown: Reactor heap range is truncated".to_string())?;
            if name == "#Strings"
                && heap
                    .iter()
                    .filter(|byte: &&u8| **byte == 0)
                    .take(MAX_REACTOR_STRING_HEAP_ENTRIES.saturating_add(1))
                    .count()
                    > MAX_REACTOR_STRING_HEAP_ENTRIES
            {
                return Err("Unknown: Reactor string heap entry cap exceeded".to_string());
            }
            selected_heap_bytes = selected_heap_bytes
                .checked_add(size)
                .ok_or_else(|| "Unknown: Reactor heap size overflowed".to_string())?;
        }
    }
    if selected_heap_bytes > MAX_REACTOR_SELECTED_HEAP_BYTES {
        return Err("Unknown: Reactor selected metadata heaps exceed the byte cap".to_string());
    }
    let table_header: StreamHeader = root
        .streams
        .get("#~")
        .or_else(|| root.streams.get("#-"))
        .copied()
        .ok_or_else(|| "Unknown: Reactor table stream is absent".to_string())?;
    let table_stream = parse_table_stream(metadata, table_header)
        .map_err(|error| format!("Unknown: Reactor table preflight failed: {error}"))?;
    let mut total_rows: u64 = 0;
    for count in table_stream.row_counts.values() {
        if usize::try_from(*count)
            .ok()
            .is_none_or(|rows: usize| rows > MAX_REACTOR_RELEVANT_METADATA_ROWS)
        {
            return Err("Unknown: Reactor metadata table row cap exceeded".to_string());
        }
        total_rows = total_rows
            .checked_add(u64::from(*count))
            .ok_or_else(|| "Unknown: Reactor metadata row total overflowed".to_string())?;
    }
    if total_rows > MAX_REACTOR_TOTAL_METADATA_ROWS {
        return Err("Unknown: Reactor metadata row total exceeds the selected bound".to_string());
    }
    Ok(())
}

fn reactor_unknown_without_view(reason: String) -> ResourceStringRecovery {
    ResourceStringRecovery {
        resource_name: String::new(),
        resource_size: 0,
        scheme: "Reactor static string resource".to_string(),
        strings: Vec::new(),
        dynamic_wall: Some(reason),
    }
}

const MAX_REACTOR_ENTRY_METHODS: usize = 256;
const MAX_REACTOR_PE_SECTIONS: usize = 96;
const MAX_REACTOR_METADATA_STREAMS: usize = 64;
const MAX_REACTOR_METADATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_REACTOR_HEAP_BYTES: usize = 16 * 1024 * 1024;
const MAX_REACTOR_SELECTED_HEAP_BYTES: usize = 32 * 1024 * 1024;
const MAX_REACTOR_STRING_HEAP_ENTRIES: usize = 262_144;
const MAX_REACTOR_TOTAL_METADATA_ROWS: u64 = 262_144;
const MAX_REACTOR_METHOD_ROWS: usize = 65_536;
const MAX_REACTOR_METHOD_INSTRUCTIONS: usize = 4096;
const MAX_REACTOR_METHOD_CODE_BYTES: u32 = 4096;
const MAX_REACTOR_METHOD_TOTAL_BYTES: usize = 16 * 1024;
const MAX_REACTOR_RELEVANT_METADATA_ROWS: usize = 65_536;
const REACTOR_FIELD_ACCESS_MASK: u16 = 0x0007;
const REACTOR_FIELD_STATIC: u16 = 0x0010;
const REACTOR_FIELD_INIT_ONLY: u16 = 0x0020;
const REACTOR_FIELD_HAS_RVA: u16 = 0x0100;
const REACTOR_FIELD_SPECIAL_NAME: u16 = 0x0200;
const REACTOR_FIELD_RT_SPECIAL_NAME: u16 = 0x0400;
const REACTOR_TYPE_LAYOUT_MASK: u32 = 0x0018;
const REACTOR_TYPE_EXPLICIT_LAYOUT: u32 = 0x0010;
const REACTOR_TYPE_INTERFACE: u32 = 0x0020;
const REACTOR_TYPE_SEALED: u32 = 0x0100;
const REACTOR_FAT_METHOD_FORMAT: u16 = 0x0003;
const REACTOR_FAT_METHOD_MORE_SECTIONS: u16 = 0x0008;
const REACTOR_FAT_METHOD_INIT_LOCALS: u16 = 0x0010;
const REACTOR_FAT_METHOD_HEADER_WORDS: u16 = 3;
const REACTOR_METHOD_ABSTRACT: u16 = 0x0400;
const REACTOR_METHOD_PINVOKE_IMPL: u16 = 0x2000;
const REACTOR_METHOD_IMPL_CODE_TYPE_MASK: u16 = 0x0003;
const REACTOR_METHOD_IMPL_UNMANAGED: u16 = 0x0004;
const REACTOR_METHOD_IMPL_FORWARD_REF: u16 = 0x0010;
const REACTOR_METHOD_IMPL_INTERNAL_CALL: u16 = 0x1000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReactorProvenance {
    resource_name: String,
    key_field_token: u32,
    iv_field_token: u32,
    reverse_iv: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactorCandidate {
    provenance: ReactorProvenance,
    key: [u8; 32],
    iv: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InitializedField {
    token: u32,
    local: u16,
    bytes: Vec<u8>,
    store_index: usize,
    instruction_indices: [usize; 6],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactorMetadataIndex {
    class_layouts: BTreeMap<u32, Option<crate::tables::ClassLayoutRow>>,
    field_rvas: BTreeMap<u32, Option<FieldRvaRow>>,
    fieldless_types: BTreeSet<u32>,
    generic_type_owners: BTreeSet<u32>,
}

impl ReactorMetadataIndex {
    fn build(resolver: &Resolver) -> std::result::Result<Self, String> {
        let tables: &crate::tables::Tables = resolver.tables();
        if tables.class_layouts.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
            || tables.field_rvas.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
            || tables.generic_params.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
            || tables.type_defs.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
            || tables.fields.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
            || tables.methods.len() > MAX_REACTOR_METHOD_ROWS
            || tables.params.len() > MAX_REACTOR_RELEVANT_METADATA_ROWS
        {
            return Err("Unknown: Reactor relevant metadata row cap exceeded".to_string());
        }
        let first_type = tables
            .type_defs
            .first()
            .ok_or_else(|| "Unknown: Reactor assembly has no TypeDef rows".to_string())?;
        if first_type.field_list != 1 || first_type.method_list != 1 {
            return Err("Unknown: Reactor TypeDef ownership does not begin at row 1".to_string());
        }
        if tables.type_defs.iter().any(|type_def| {
            type_def
                .extends
                .is_some_and(|base: RowRef| base.table == TableId::TypeSpec)
        }) {
            return Err("Unknown: Reactor TypeSpec base types are unsupported".to_string());
        }
        let field_end: u32 = u32::try_from(tables.fields.len())
            .ok()
            .and_then(|count: u32| count.checked_add(1))
            .ok_or_else(|| "Unknown: Reactor Field row count overflowed".to_string())?;
        let method_end: u32 = u32::try_from(tables.methods.len())
            .ok()
            .and_then(|count: u32| count.checked_add(1))
            .ok_or_else(|| "Unknown: Reactor MethodDef row count overflowed".to_string())?;
        let param_end: u32 = u32::try_from(tables.params.len())
            .ok()
            .and_then(|count: u32| count.checked_add(1))
            .ok_or_else(|| "Unknown: Reactor Param row count overflowed".to_string())?;
        if let Some(first_method) = tables.methods.first()
            && first_method.param_list != 1
        {
            return Err("Unknown: Reactor Param ownership does not begin at row 1".to_string());
        }
        for (index, method) in tables.methods.iter().enumerate() {
            let next_param: u32 = tables
                .methods
                .get(index.saturating_add(1))
                .map_or(param_end, |next| next.param_list);
            if method.param_list == 0
                || method.param_list > param_end
                || next_param < method.param_list
                || next_param > param_end
            {
                return Err("Unknown: Reactor MethodDef Param ranges are invalid".to_string());
            }
        }
        let mut fieldless_types: BTreeSet<u32> = BTreeSet::new();
        for (index, type_def) in tables.type_defs.iter().enumerate() {
            let next_field: u32 = tables
                .type_defs
                .get(index.saturating_add(1))
                .map_or(field_end, |next| next.field_list);
            let next_method: u32 = tables
                .type_defs
                .get(index.saturating_add(1))
                .map_or(method_end, |next| next.method_list);
            if type_def.field_list == 0
                || type_def.field_list > field_end
                || next_field < type_def.field_list
                || next_field > field_end
                || type_def.method_list == 0
                || type_def.method_list > method_end
                || next_method < type_def.method_list
                || next_method > method_end
            {
                return Err("Unknown: Reactor TypeDef ownership ranges are invalid".to_string());
            }
            if type_def.field_list == next_field {
                let rid: u32 = u32::try_from(index)
                    .ok()
                    .and_then(|value: u32| value.checked_add(1))
                    .ok_or_else(|| "Unknown: Reactor TypeDef row index overflowed".to_string())?;
                fieldless_types.insert(rid);
            }
        }
        let mut class_layouts: BTreeMap<u32, Option<crate::tables::ClassLayoutRow>> =
            BTreeMap::new();
        for layout in &tables.class_layouts {
            match class_layouts.get_mut(&layout.parent) {
                Some(unique) => *unique = None,
                None => {
                    class_layouts.insert(layout.parent, Some(*layout));
                }
            }
        }
        let mut field_rvas: BTreeMap<u32, Option<FieldRvaRow>> = BTreeMap::new();
        for field_rva in &tables.field_rvas {
            match field_rvas.get_mut(&field_rva.field) {
                Some(unique) => *unique = None,
                None => {
                    field_rvas.insert(field_rva.field, Some(*field_rva));
                }
            }
        }
        let generic_type_owners: BTreeSet<u32> = tables
            .generic_params
            .iter()
            .filter_map(|parameter| parameter.owner)
            .filter(|owner: &RowRef| owner.table == TableId::TypeDef)
            .map(|owner: RowRef| owner.row)
            .collect();
        Ok(Self {
            class_layouts,
            field_rvas,
            fieldless_types,
            generic_type_owners,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReactorFlow {
    pub(super) successors: Vec<Vec<usize>>,
    reachable: Vec<bool>,
    dominance: Option<FlowGraph<usize>>,
}

fn derive(successors: &[Vec<usize>]) -> (Vec<bool>, Option<FlowGraph<usize>>) {
    let mut reachable: Vec<bool> = vec![false; successors.len()];
    let mut pending: Vec<usize> = vec![0];
    while let Some(index) = pending.pop() {
        let Some(slot): Option<&mut bool> = reachable.get_mut(index) else {
            continue;
        };
        if *slot {
            continue;
        }
        *slot = true;
        if let Some(targets) = successors.get(index) {
            pending.extend(targets.iter().copied());
        }
    }
    let dominance: Option<FlowGraph<usize>> = FlowGraph::build(
        0..successors.len(),
        0,
        |index: usize, emit: &mut dyn FnMut(Flow<usize>)| {
            let Some(targets): Option<&Vec<usize>> = successors.get(index) else {
                return;
            };
            if targets.is_empty() {
                emit(Flow::Exit);
            }
            for target in targets {
                emit(Flow::To(*target));
            }
        },
    )
    .ok();
    (reachable, dominance)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReactorCallShape {
    AesCreate,
    CreateDecryptor,
    SetCipherMode,
    SetPaddingMode,
    SetByteArray,
    GetExecutingAssembly,
    GetManifestResourceStream,
    InitializeArray,
    ReverseArray,
    CryptoStreamConstructor,
    MemoryStreamConstructor,
    InvalidDataExceptionConstructor,
    StreamCopyTo,
    MemoryStreamToArray,
    Dispose,
    BitConverterToInt32,
    EncodingUnicode,
    EncodingGetString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalBinding {
    local: u16,
    producer_index: usize,
    store_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResourceBinding {
    name: String,
    local: u16,
    call_index: usize,
    store_index: usize,
    instruction_indices: Vec<usize>,
}

impl ReactorFlow {
    pub(super) fn build(body: &MethodBody) -> std::result::Result<Self, String> {
        if body.instructions.is_empty() {
            return Err("method has no instructions".to_string());
        }
        let offsets: BTreeMap<u32, usize> = body
            .instructions
            .iter()
            .enumerate()
            .map(|(index, instruction): (usize, &Instruction)| (instruction.offset, index))
            .collect();
        if offsets.len() != body.instructions.len() {
            return Err("method has duplicate instruction offsets".to_string());
        }
        let mut successors: Vec<Vec<usize>> = vec![Vec::new(); body.instructions.len()];
        for (index, instruction) in body.instructions.iter().enumerate() {
            if instruction.name == "jmp" {
                return Err(format!(
                    "jmp at IL_{:04X} is outside the selected control-flow slice",
                    instruction.offset
                ));
            }
            let fallthrough: Option<usize> =
                index.checked_add(1).filter(|next| *next < successors.len());
            let next_offset: u32 = fallthrough
                .and_then(|next: usize| body.instructions.get(next))
                .map_or(body.code_size, |next: &Instruction| next.offset);
            let targets: Vec<usize> = match instruction.flow {
                FlowControl::Return | FlowControl::Throw => Vec::new(),
                FlowControl::Branch => {
                    let OperandValue::BrTarget(relative): &OperandValue = &instruction.operand
                    else {
                        return Err(format!(
                            "branch at IL_{:04X} has no relative target",
                            instruction.offset
                        ));
                    };
                    vec![reactor_target_index(
                        &offsets,
                        instruction,
                        *relative,
                        next_offset,
                    )?]
                }
                FlowControl::CondBranch => match &instruction.operand {
                    OperandValue::BrTarget(relative) => {
                        let mut targets: Vec<usize> = vec![reactor_target_index(
                            &offsets,
                            instruction,
                            *relative,
                            next_offset,
                        )?];
                        if let Some(next) = fallthrough {
                            targets.push(next);
                        }
                        targets
                    }
                    OperandValue::Switch(relative_targets) => {
                        let mut targets: Vec<usize> = Vec::with_capacity(
                            relative_targets
                                .len()
                                .saturating_add(usize::from(fallthrough.is_some())),
                        );
                        for relative in relative_targets {
                            let target: usize = reactor_target_index(
                                &offsets,
                                instruction,
                                *relative,
                                next_offset,
                            )?;
                            if !targets.contains(&target) {
                                targets.push(target);
                            }
                        }
                        if let Some(next) = fallthrough
                            && !targets.contains(&next)
                        {
                            targets.push(next);
                        }
                        targets
                    }
                    _ => {
                        return Err(format!(
                            "conditional branch at IL_{:04X} has no target",
                            instruction.offset
                        ));
                    }
                },
                FlowControl::Next | FlowControl::Call | FlowControl::Break | FlowControl::Meta => {
                    fallthrough.into_iter().collect()
                }
            };
            successors[index] = targets;
        }
        let (reachable, dominance): (Vec<bool>, Option<FlowGraph<usize>>) = derive(&successors);
        let flow: Self = Self {
            successors,
            reachable,
            dominance,
        };
        if flow.has_reachable_cycle() {
            return Err("reachable control flow contains a cycle".to_string());
        }
        Ok(flow)
    }

    #[cfg(test)]
    pub(super) fn add_edge(&mut self, from: usize, to: usize) {
        let Some(targets): Option<&mut Vec<usize>> = self.successors.get_mut(from) else {
            return;
        };
        targets.push(to);
        let (reachable, dominance): (Vec<bool>, Option<FlowGraph<usize>>) =
            derive(&self.successors);
        self.reachable = reachable;
        self.dominance = dominance;
    }

    fn is_reachable(&self, index: usize) -> bool {
        self.reachable.get(index).copied().unwrap_or(false)
    }

    fn dominates(&self, dominator: usize, target: usize) -> bool {
        self.dominance
            .as_ref()
            .is_some_and(|flow: &FlowGraph<usize>| flow.dominates(dominator, target))
    }

    fn has_edge(&self, from: usize, to: usize) -> bool {
        self.successors
            .get(from)
            .is_some_and(|targets: &Vec<usize>| targets.contains(&to))
    }

    pub(super) fn has_reachable_cycle(&self) -> bool {
        let mut indegrees: Vec<usize> = vec![0; self.successors.len()];
        let mut reachable_count: usize = 0;
        for (source, targets) in self.successors.iter().enumerate() {
            if !self.is_reachable(source) {
                continue;
            }
            reachable_count = reachable_count.saturating_add(1);
            for target in targets {
                if self.is_reachable(*target) {
                    let Some(next): Option<usize> = indegrees[*target].checked_add(1) else {
                        return true;
                    };
                    indegrees[*target] = next;
                }
            }
        }
        let mut pending: Vec<usize> = indegrees
            .iter()
            .enumerate()
            .filter(|(index, indegree): &(usize, &usize)| {
                self.is_reachable(*index) && **indegree == 0
            })
            .map(|(index, _): (usize, &usize)| index)
            .collect();
        let mut processed: usize = 0;
        while let Some(source) = pending.pop() {
            processed = processed.saturating_add(1);
            for target in &self.successors[source] {
                if !self.is_reachable(*target) {
                    continue;
                }
                let Some(next): Option<usize> = indegrees[*target].checked_sub(1) else {
                    return true;
                };
                indegrees[*target] = next;
                if next == 0 {
                    pending.push(*target);
                }
            }
        }
        processed != reachable_count
    }
}

fn reactor_target_index(
    offsets: &BTreeMap<u32, usize>,
    instruction: &Instruction,
    relative: i32,
    next_offset: u32,
) -> std::result::Result<usize, String> {
    let checked_target: u32 =
        u32::try_from(i64::from(next_offset) + i64::from(relative)).map_err(|_| {
            format!(
                "branch at IL_{:04X} targets outside the method",
                instruction.offset
            )
        })?;
    let target: u32 = absolute_target(instruction, relative, next_offset);
    if target != checked_target {
        return Err(format!(
            "branch at IL_{:04X} target calculation is inconsistent",
            instruction.offset
        ));
    }
    offsets.get(&target).copied().ok_or_else(|| {
        format!(
            "branch at IL_{:04X} targets missing IL_{target:04X}",
            instruction.offset
        )
    })
}

fn discover_reactor_static_candidate(
    image: &[u8],
    view: &ImageView,
) -> std::result::Result<Option<ReactorCandidate>, String> {
    if view.tables.methods.len() > MAX_REACTOR_METHOD_ROWS {
        return Err("Unknown: Reactor method row cap exceeded".to_string());
    }
    let root: MetadataRoot = parse_metadata_root(image, &view.pe, &view.clr)
        .map_err(|error| format!("Unknown: Reactor metadata parse failed: {error}"))?;
    let resolver: Resolver = Resolver::build(image, &view.pe, &view.clr, &root)
        .map_err(|error| format!("Unknown: Reactor metadata model failed: {error}"))?;
    let metadata_index: ReactorMetadataIndex = ReactorMetadataIndex::build(&resolver)?;
    let model: crate::model::AssemblyModel = resolver.model();
    let embedded_count: usize = view
        .tables
        .manifest_resources
        .iter()
        .filter(|row: &&ManifestResourceRow| row.implementation.is_none())
        .count();
    if embedded_count > MAX_EMBEDDED_RESOURCES {
        return Err("Unknown: Reactor embedded-resource cap exceeded".to_string());
    }
    let resource_names: BTreeSet<String> = embedded_resource_names(view);
    if resource_names.is_empty() {
        return Ok(None);
    }
    let mut candidates: BTreeMap<ReactorProvenance, ReactorCandidate> = BTreeMap::new();
    let mut analyzed_helpers: BTreeMap<u32, Option<ReactorCandidate>> = BTreeMap::new();
    let mut entries_seen: usize = 0;
    for ty in &model.types {
        let helper_tokens: BTreeSet<u32> = ty
            .methods
            .iter()
            .filter(|method: &&MethodModel| is_reactor_resource_helper(&resolver, method))
            .map(|method: &MethodModel| method.token)
            .collect();
        if helper_tokens.is_empty() {
            continue;
        }
        for entry in &ty.methods {
            if !is_reactor_string_entry(&resolver, entry) {
                continue;
            }
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or_else(|| "Unknown: Reactor string entry count overflowed".to_string())?;
            if entries_seen > MAX_REACTOR_ENTRY_METHODS {
                return Err("Unknown: Reactor string entry method cap exceeded".to_string());
            }
            let Ok(entry_body): std::result::Result<MethodBody, String> =
                reactor_method_body(image, &view.pe, entry.rva)
            else {
                continue;
            };
            let Some(helper_token): Option<u32> =
                reactor_entry_helper(&resolver, &entry_body, &helper_tokens)?
            else {
                continue;
            };
            let candidate: Option<ReactorCandidate> = if let Some(cached) =
                analyzed_helpers.get(&helper_token)
            {
                cached.clone()
            } else {
                let helper: &MethodModel = method_by_token(ty, helper_token).ok_or_else(|| {
                    format!("Unknown: Reactor helper 0x{helper_token:08X} disappeared")
                })?;
                let helper_body: MethodBody = reactor_method_body(image, &view.pe, helper.rva)
                        .map_err(|reason: String| {
                            format!(
                                "Unknown: Reactor helper method 0x{helper_token:08X} is invalid: {reason}"
                            )
                        })?;
                let analyzed: Option<ReactorCandidate> = analyze_reactor_helper(
                    image,
                    view,
                    &resolver,
                    &metadata_index,
                    helper,
                    &helper_body,
                    &resource_names,
                )?;
                analyzed_helpers.insert(helper_token, analyzed.clone());
                analyzed
            };
            if let Some(candidate) = candidate {
                candidates
                    .entry(candidate.provenance.clone())
                    .or_insert(candidate);
            }
        }
    }
    if candidates.len() > 1 {
        return Err(format!(
            "Unknown: Reactor static analysis found {} distinct resource/key/IV tuples",
            candidates.len()
        ));
    }
    if entries_seen != 0 && candidates.is_empty() {
        return Err(
            "Unknown: Reactor string entry CIL is outside the selected static slice".to_string(),
        );
    }
    Ok(candidates.into_values().next())
}

fn reactor_entry_helper(
    resolver: &Resolver,
    body: &MethodBody,
    helper_tokens: &BTreeSet<u32>,
) -> std::result::Result<Option<u32>, String> {
    let semantic_indices: Vec<usize> = body
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction): &(usize, &Instruction)| instruction.name != "nop")
        .map(|(index, _): (usize, &Instruction)| index)
        .collect();
    let semantic_instructions: Vec<&Instruction> = semantic_indices
        .iter()
        .filter_map(|index: &usize| body.instructions.get(*index))
        .collect();
    let Some(helper_call): Option<&&Instruction> = semantic_instructions.first() else {
        return Ok(None);
    };
    let Some(helper_token): Option<u32> = direct_static_helper_token(helper_call, helper_tokens)
    else {
        return Ok(None);
    };
    if !body.exception_clauses.is_empty() {
        return Err("Unknown: Reactor string entry contains exception regions".to_string());
    }
    if body.max_stack < 4 {
        return Err("Unknown: Reactor string entry max stack is below 4".to_string());
    }
    let flow: ReactorFlow = ReactorFlow::build(body).map_err(|reason: String| {
        format!("Unknown: Reactor string entry flow is invalid: {reason}")
    })?;
    let local_types: Vec<TypeSig> = reactor_local_types(resolver, body)?;
    let Some(core): Option<&[&Instruction]> = semantic_instructions.get(..13) else {
        return Err("Unknown: Reactor string entry is truncated".to_string());
    };
    let [
        _,
        data_store,
        data_for_length,
        offset_for_length,
        to_int32,
        length_store,
        encoding_unicode,
        data_for_string,
        offset_for_string,
        prefix_length,
        add_prefix,
        length_for_string,
        get_string,
    ]: [&Instruction; 13] = core.try_into().map_err(|_| {
        "Unknown: Reactor string entry core has the wrong instruction count".to_string()
    })?;
    let core_indices: &[usize] = semantic_indices
        .get(..13)
        .ok_or_else(|| "Unknown: Reactor string entry core indices are absent".to_string())?;
    if !nop_separated_dominating(body, &flow, core_indices) {
        return Err("Unknown: Reactor string entry core is not straight-line".to_string());
    }
    let core_last: usize = *core_indices
        .last()
        .ok_or_else(|| "Unknown: Reactor string entry core is absent".to_string())?;
    let return_index: usize = match semantic_indices.as_slice() {
        [.., ret] if semantic_indices.len() == 14 => {
            let instruction: &Instruction = body
                .instructions
                .get(*ret)
                .ok_or_else(|| "Unknown: Reactor string return is absent".to_string())?;
            if instruction.name != "ret" || !flow.dominates(core_last, *ret) {
                return Err("Unknown: Reactor string entry direct return is invalid".to_string());
            }
            *ret
        }
        [.., store, branch, load, ret] if semantic_indices.len() == 17 => {
            let result_local: u16 = body
                .instructions
                .get(*store)
                .and_then(local_store_index)
                .ok_or_else(|| "Unknown: Reactor string result store is invalid".to_string())?;
            if local_types.get(usize::from(result_local)) != Some(&TypeSig::String)
                || body.instructions.get(*load).and_then(local_load_index) != Some(result_local)
                || body
                    .instructions
                    .get(*branch)
                    .is_none_or(|instruction: &Instruction| {
                        !matches!(instruction.name.as_str(), "br" | "br.s")
                    })
                || !flow.has_edge(*branch, *load)
                || body
                    .instructions
                    .get(*ret)
                    .is_none_or(|instruction: &Instruction| instruction.name != "ret")
                || !flow.dominates(core_last, *store)
                || !flow.dominates(*store, *load)
                || !flow.dominates(*load, *ret)
            {
                return Err("Unknown: Reactor string entry local return is invalid".to_string());
            }
            *ret
        }
        _ => {
            return Err(format!(
                "Unknown: Reactor string entry has {} semantic instructions",
                semantic_indices.len()
            ));
        }
    };
    if flow
        .successors
        .get(return_index)
        .is_none_or(|successors: &Vec<usize>| !successors.is_empty())
    {
        return Err("Unknown: Reactor string entry return has successors".to_string());
    }
    let data_local: u16 = local_store_index(data_store)
        .ok_or_else(|| "Unknown: Reactor string entry does not store helper bytes".to_string())?;
    let length_local: u16 = local_store_index(length_store)
        .filter(|local: &u16| *local != data_local)
        .ok_or_else(|| "Unknown: Reactor string entry does not store record length".to_string())?;
    if local_types.get(usize::from(data_local)) != Some(&TypeSig::SzArray(Box::new(TypeSig::U1)))
        || local_types.get(usize::from(length_local)) != Some(&TypeSig::I4)
        || local_load_index(data_for_length) != Some(data_local)
        || offset_for_length.name != "ldarg.0"
        || !instruction_matches_framework_call(
            resolver,
            to_int32,
            "System",
            "BitConverter",
            "ToInt32",
            ReactorCallShape::BitConverterToInt32,
        )
        || !instruction_matches_framework_call(
            resolver,
            encoding_unicode,
            "System.Text",
            "Encoding",
            "get_Unicode",
            ReactorCallShape::EncodingUnicode,
        )
        || local_load_index(data_for_string) != Some(data_local)
        || offset_for_string.name != "ldarg.0"
        || int_literal(prefix_length) != Some(4)
        || add_prefix.name != "add"
        || local_load_index(length_for_string) != Some(length_local)
        || !instruction_matches_framework_call(
            resolver,
            get_string,
            "System.Text",
            "Encoding",
            "GetString",
            ReactorCallShape::EncodingGetString,
        )
    {
        return Err(
            "Unknown: Reactor string entry record dataflow is outside the selected slice"
                .to_string(),
        );
    }
    Ok(Some(helper_token))
}

fn analyze_reactor_helper(
    image: &[u8],
    view: &ImageView,
    resolver: &Resolver,
    metadata_index: &ReactorMetadataIndex,
    helper: &MethodModel,
    body: &MethodBody,
    resource_names: &BTreeSet<String>,
) -> std::result::Result<Option<ReactorCandidate>, String> {
    if !is_reactor_resource_helper(resolver, helper) {
        return Ok(None);
    }
    if !body.exception_clauses.is_empty() {
        return Err("Unknown: Reactor helper contains exception regions".to_string());
    }
    if body.max_stack < 3 {
        return Err("Unknown: Reactor helper max stack is below 3".to_string());
    }
    let local_types: Vec<TypeSig> = reactor_local_types(resolver, body)?;
    let flow: ReactorFlow = ReactorFlow::build(body).map_err(|reason: String| {
        format!("Unknown: Reactor helper control flow is invalid: {reason}")
    })?;
    let aes_create_calls: Vec<(usize, &Instruction)> = framework_calls(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "Aes",
        "Create",
    );
    if aes_create_calls.is_empty() {
        return Ok(None);
    }
    let aes_create: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "Aes",
        "Create",
        ReactorCallShape::AesCreate,
    )?;
    let aes: LocalBinding = stored_call_result(body, &flow, aes_create, "AES factory")?;
    let mode_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "set_Mode",
        ReactorCallShape::SetCipherMode,
    )?;
    require_enum_assignment(body, &flow, mode_call, aes.local, 1, "CBC mode")?;
    let padding_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "set_Padding",
        ReactorCallShape::SetPaddingMode,
    )?;
    require_enum_assignment(body, &flow, padding_call, aes.local, 2, "PKCS#7 padding")?;
    let initialized: Vec<InitializedField> =
        initialized_field_locals(image, view, resolver, metadata_index, body, &flow)?;
    let keys: Vec<&InitializedField> = initialized
        .iter()
        .filter(|field: &&InitializedField| field.bytes.len() == 32)
        .collect();
    let ivs: Vec<&InitializedField> = initialized
        .iter()
        .filter(|field: &&InitializedField| field.bytes.len() == 16)
        .collect();
    if keys.len() != 1 || ivs.len() != 1 {
        return Err(format!(
            "Unknown: Reactor AES helper has {} exact 32-byte key fields and {} exact 16-byte IV fields",
            keys.len(),
            ivs.len()
        ));
    }
    let key_field: &InitializedField = keys[0];
    let iv_field: &InitializedField = ivs[0];
    let key_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "set_Key",
        ReactorCallShape::SetByteArray,
    )?;
    require_local_assignment(body, &flow, key_call, aes.local, key_field.local, "AES key")?;
    let iv_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "set_IV",
        ReactorCallShape::SetByteArray,
    )?;
    require_local_assignment(body, &flow, iv_call, aes.local, iv_field.local, "AES IV")?;
    let reverse_calls: Vec<(usize, &Instruction)> =
        framework_calls(resolver, body, &flow, "System", "Array", "Reverse");
    if reverse_calls.len() > 1 {
        return Err("Unknown: Reactor has multiple reachable array reversals".to_string());
    }
    let reverse_call: Option<usize> = reverse_calls.first().map(|(index, _)| *index);
    if let Some(index) = reverse_call {
        let instruction: &Instruction = body
            .instructions
            .get(index)
            .ok_or_else(|| "Unknown: Reactor reversal instruction disappeared".to_string())?;
        if !call_shape_matches(resolver, instruction, ReactorCallShape::ReverseArray)
            || !require_single_local_argument(body, &flow, index, iv_field.local)
        {
            return Err("Unknown: Reactor array reversal is not bound to the IV".to_string());
        }
    }
    let resource: ResourceBinding = resource_binding(resolver, body, &flow)?;
    if !resource_names.contains(&resource.name) {
        return Err("Unknown: Reactor referenced resource is not embedded".to_string());
    }
    let decryptor_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "CreateDecryptor",
        ReactorCallShape::CreateDecryptor,
    )?;
    if !require_single_local_argument(body, &flow, decryptor_call, aes.local) {
        return Err(
            "Unknown: Reactor decryptor is not created from the selected AES local".to_string(),
        );
    }
    let transform: LocalBinding = stored_call_result(body, &flow, decryptor_call, "AES decryptor")?;
    let crypto_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "CryptoStream",
        ".ctor",
        ReactorCallShape::CryptoStreamConstructor,
    )?;
    require_crypto_stream_arguments(body, &flow, crypto_call, resource.local, transform.local)?;
    let crypto: LocalBinding =
        stored_call_result(body, &flow, crypto_call, "CryptoStream constructor")?;
    let memory_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.IO",
        "MemoryStream",
        ".ctor",
        ReactorCallShape::MemoryStreamConstructor,
    )?;
    let memory: LocalBinding =
        stored_call_result(body, &flow, memory_call, "MemoryStream constructor")?;
    let copy_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.IO",
        "Stream",
        "CopyTo",
        ReactorCallShape::StreamCopyTo,
    )?;
    require_local_assignment(
        body,
        &flow,
        copy_call,
        crypto.local,
        memory.local,
        "decrypted stream copy",
    )?;
    let aes_dispose: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.Security.Cryptography",
        "SymmetricAlgorithm",
        "Dispose",
        ReactorCallShape::Dispose,
    )?;
    if !require_single_local_argument(body, &flow, aes_dispose, aes.local) {
        return Err("Unknown: Reactor AES disposal is not bound to the selected local".to_string());
    }
    let resource_dispose: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.IO",
        "Stream",
        "Dispose",
        ReactorCallShape::Dispose,
    )?;
    if !require_single_local_argument(body, &flow, resource_dispose, resource.local) {
        return Err(
            "Unknown: Reactor resource disposal is not bound to the selected local".to_string(),
        );
    }
    let to_array_call: usize = unique_framework_call(
        resolver,
        body,
        &flow,
        "System.IO",
        "MemoryStream",
        "ToArray",
        ReactorCallShape::MemoryStreamToArray,
    )?;
    if !require_single_local_argument(body, &flow, to_array_call, memory.local) {
        return Err(
            "Unknown: Reactor plaintext output is not read from the selected memory stream"
                .to_string(),
        );
    }
    let aes_dispose_load: usize = prior_index(aes_dispose, 1, "AES disposal")?;
    let resource_dispose_load: usize = prior_index(resource_dispose, 1, "resource disposal")?;
    let to_array_memory_load: usize = prior_index(to_array_call, 1, "plaintext output")?;
    let disposal_tail: [usize; 7] = [
        copy_call,
        aes_dispose_load,
        aes_dispose,
        resource_dispose_load,
        resource_dispose,
        to_array_memory_load,
        to_array_call,
    ];
    if !nop_separated_dominating(body, &flow, &disposal_tail) {
        return Err("Unknown: Reactor helper has no exact post-copy disposal tail".to_string());
    }
    let result: LocalBinding = stored_call_result(body, &flow, to_array_call, "plaintext array")?;
    let return_index: usize = exact_local_return_tail(body, &flow, &result)?;
    if local_types.get(usize::from(key_field.local))
        != Some(&TypeSig::SzArray(Box::new(TypeSig::U1)))
        || local_types.get(usize::from(iv_field.local))
            != Some(&TypeSig::SzArray(Box::new(TypeSig::U1)))
        || local_types.get(usize::from(result.local))
            != Some(&TypeSig::SzArray(Box::new(TypeSig::U1)))
        || local_types
            .get(usize::from(aes.local))
            .is_none_or(|signature: &TypeSig| {
                !named_type(
                    resolver,
                    signature,
                    false,
                    "System.Security.Cryptography",
                    "Aes",
                )
            })
        || local_types
            .get(usize::from(resource.local))
            .is_none_or(|signature: &TypeSig| {
                !named_type(resolver, signature, false, "System.IO", "Stream")
            })
        || local_types
            .get(usize::from(transform.local))
            .is_none_or(|signature: &TypeSig| {
                !named_type(
                    resolver,
                    signature,
                    false,
                    "System.Security.Cryptography",
                    "ICryptoTransform",
                )
            })
        || local_types
            .get(usize::from(crypto.local))
            .is_none_or(|signature: &TypeSig| {
                !named_type(
                    resolver,
                    signature,
                    false,
                    "System.Security.Cryptography",
                    "CryptoStream",
                )
            })
        || local_types
            .get(usize::from(memory.local))
            .is_none_or(|signature: &TypeSig| {
                !named_type(resolver, signature, false, "System.IO", "MemoryStream")
            })
    {
        return Err(
            "Unknown: Reactor helper local signature is outside the selected slice".to_string(),
        );
    }
    let before_decryptor: [usize; 8] = [
        key_field.store_index,
        iv_field.store_index,
        aes.producer_index,
        aes.store_index,
        mode_call,
        padding_call,
        key_call,
        iv_call,
    ];
    let before_crypto: [usize; 4] = [
        resource.call_index,
        resource.store_index,
        decryptor_call,
        transform.store_index,
    ];
    if before_decryptor
        .iter()
        .any(|index: &usize| !flow.dominates(*index, decryptor_call))
        || reverse_call.is_some_and(|index: usize| {
            !flow.dominates(index, iv_call) || !flow.dominates(index, decryptor_call)
        })
        || before_crypto
            .iter()
            .any(|index: &usize| !flow.dominates(*index, crypto_call))
        || !flow.dominates(crypto_call, crypto.store_index)
        || !flow.dominates(crypto.store_index, copy_call)
        || !flow.dominates(memory.store_index, copy_call)
        || !flow.dominates(copy_call, aes_dispose)
        || !flow.dominates(aes_dispose, resource_dispose)
        || !flow.dominates(resource_dispose, to_array_call)
        || !flow.dominates(to_array_call, result.store_index)
        || !flow.dominates(result.store_index, return_index)
    {
        return Err(
            "Unknown: Reactor decryption provenance does not dominate the returned bytes"
                .to_string(),
        );
    }
    let key_value_load: usize = prior_index(key_call, 1, "AES key")?;
    let iv_value_load: usize = prior_index(iv_call, 1, "AES IV")?;
    let mode_receiver: usize = prior_index(mode_call, 2, "CBC mode")?;
    let padding_receiver: usize = prior_index(padding_call, 2, "PKCS#7 padding")?;
    let key_receiver: usize = prior_index(key_call, 2, "AES key")?;
    let iv_receiver: usize = prior_index(iv_call, 2, "AES IV")?;
    let decryptor_receiver: usize = prior_index(decryptor_call, 1, "AES decryptor")?;
    let crypto_stream_load: usize = prior_index(crypto_call, 3, "CryptoStream resource")?;
    let crypto_transform_load: usize = prior_index(crypto_call, 2, "CryptoStream decryptor")?;
    let copy_crypto_load: usize = prior_index(copy_call, 2, "decrypted stream copy")?;
    let copy_memory_load: usize = prior_index(copy_call, 1, "decrypted stream copy")?;
    validate_local_provenance(
        body,
        &flow,
        key_field.local,
        key_field.store_index,
        &[key_value_load],
        "key",
    )?;
    let mut iv_loads: Vec<usize> = vec![iv_value_load];
    if let Some(index) = reverse_call {
        iv_loads.push(prior_index(index, 1, "IV reversal")?);
    }
    validate_local_provenance(
        body,
        &flow,
        iv_field.local,
        iv_field.store_index,
        &iv_loads,
        "IV",
    )?;
    validate_local_provenance(
        body,
        &flow,
        aes.local,
        aes.store_index,
        &[
            mode_receiver,
            padding_receiver,
            key_receiver,
            iv_receiver,
            decryptor_receiver,
            aes_dispose_load,
        ],
        "AES",
    )?;
    validate_local_provenance(
        body,
        &flow,
        resource.local,
        resource.store_index,
        &[crypto_stream_load, resource_dispose_load],
        "resource stream",
    )?;
    validate_local_provenance(
        body,
        &flow,
        transform.local,
        transform.store_index,
        &[crypto_transform_load],
        "decryptor",
    )?;
    validate_local_provenance(
        body,
        &flow,
        crypto.local,
        crypto.store_index,
        &[copy_crypto_load],
        "CryptoStream",
    )?;
    validate_local_provenance(
        body,
        &flow,
        memory.local,
        memory.store_index,
        &[copy_memory_load, to_array_memory_load],
        "MemoryStream",
    )?;
    let return_result_load: usize = prior_index(return_index, 1, "plaintext return")?;
    validate_local_provenance(
        body,
        &flow,
        result.local,
        result.store_index,
        &[return_result_load],
        "plaintext result",
    )?;
    let mut selected_instructions: BTreeSet<usize> = BTreeSet::new();
    for field in &initialized {
        selected_instructions.extend(field.instruction_indices);
    }
    selected_instructions.extend(resource.instruction_indices.iter().copied());
    selected_instructions.extend([
        aes.producer_index,
        aes.store_index,
        transform.store_index,
        crypto.store_index,
        memory_call,
        memory.store_index,
        result.store_index,
    ]);
    for (call, distance, label) in [
        (mode_call, 2, "CBC mode"),
        (padding_call, 2, "PKCS#7 padding"),
        (key_call, 2, "AES key"),
        (iv_call, 2, "AES IV"),
        (decryptor_call, 1, "AES decryptor"),
        (crypto_call, 3, "CryptoStream constructor"),
        (copy_call, 2, "decrypted stream copy"),
        (aes_dispose, 1, "AES disposal"),
        (resource_dispose, 1, "resource disposal"),
        (to_array_call, 1, "plaintext output"),
    ] {
        let start: usize = prior_index(call, distance, label)?;
        selected_instructions.extend(start..=call);
    }
    if let Some(reverse) = reverse_call {
        let load: usize = prior_index(reverse, 1, "IV reversal")?;
        selected_instructions.extend(load..=reverse);
    }
    for (index, instruction) in body.instructions.iter().enumerate() {
        if index > result.store_index && flow.is_reachable(index) && instruction.name != "nop" {
            selected_instructions.insert(index);
        }
    }
    if body
        .instructions
        .iter()
        .enumerate()
        .any(|(index, instruction): (usize, &Instruction)| {
            flow.is_reachable(index)
                && instruction.name != "nop"
                && !selected_instructions.contains(&index)
        })
    {
        return Err("Unknown: Reactor helper contains unselected reachable CIL".to_string());
    }
    let key: [u8; 32] = key_field
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Unknown: Reactor key size changed during analysis".to_string())?;
    let iv: [u8; 16] = iv_field
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Unknown: Reactor IV size changed during analysis".to_string())?;
    Ok(Some(ReactorCandidate {
        provenance: ReactorProvenance {
            resource_name: resource.name,
            key_field_token: key_field.token,
            iv_field_token: iv_field.token,
            reverse_iv: reverse_call.is_some(),
        },
        key,
        iv,
    }))
}

fn initialized_field_locals(
    image: &[u8],
    view: &ImageView,
    resolver: &Resolver,
    metadata_index: &ReactorMetadataIndex,
    body: &MethodBody,
    flow: &ReactorFlow,
) -> std::result::Result<Vec<InitializedField>, String> {
    let mut fields: Vec<InitializedField> = Vec::new();
    let mut matched_initializers: usize = 0;
    for (start, window) in body.instructions.windows(6).enumerate() {
        let [
            load_length,
            new_array,
            duplicate,
            load_token,
            initialize,
            store_local,
        ] = window
        else {
            continue;
        };
        let Some(length): Option<i64> = int_literal(load_length) else {
            continue;
        };
        if !matches!(length, 16 | 32) || new_array.name != "newarr" || duplicate.name != "dup" {
            continue;
        }
        let OperandValue::Token(element_token): &OperandValue = &new_array.operand else {
            continue;
        };
        if !framework_type_matches(resolver, *element_token, "System", "Byte") {
            continue;
        }
        let OperandValue::Token(field_token): &OperandValue = &load_token.operand else {
            continue;
        };
        if load_token.name != "ldtoken" || token_table(*field_token) != Some(TableId::Field) {
            continue;
        }
        if !instruction_matches_framework_call(
            resolver,
            initialize,
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "InitializeArray",
            ReactorCallShape::InitializeArray,
        ) {
            continue;
        }
        let Some(local): Option<u16> = local_store_index(store_local) else {
            continue;
        };
        matched_initializers = matched_initializers
            .checked_add(1)
            .ok_or_else(|| "Unknown: Reactor initialized-field count overflowed".to_string())?;
        if matched_initializers > 2 {
            return Err(
                "Unknown: Reactor helper has more than two exact array initializers".to_string(),
            );
        }
        let indices: [usize; 6] = [start, start + 1, start + 2, start + 3, start + 4, start + 5];
        if !contiguous_dominating(flow, &indices) {
            return Err(
                "Unknown: Reactor array initializer has alternate control-flow predecessors"
                    .to_string(),
            );
        }
        let Some(bytes): Option<Vec<u8>> =
            exact_field_rva_bytes(image, view, resolver, metadata_index, *field_token)
        else {
            return Err(format!(
                "Unknown: Reactor initialized field 0x{field_token:08X} lacks one exact bounded FieldRVA layout"
            ));
        };
        if usize::try_from(length).ok() != Some(bytes.len()) {
            return Err(format!(
                "Unknown: Reactor initialized field 0x{field_token:08X} length does not match its array allocation"
            ));
        }
        if fields.iter().any(|field: &InitializedField| {
            field.local == local
                && (field.token != *field_token
                    || field.bytes != bytes
                    || field.store_index != start + 5)
        }) {
            return Err(format!(
                "Unknown: Reactor local {local} has conflicting initialized fields"
            ));
        }
        if !fields
            .iter()
            .any(|field: &InitializedField| field.local == local && field.token == *field_token)
        {
            fields.push(InitializedField {
                token: *field_token,
                local,
                bytes,
                store_index: start + 5,
                instruction_indices: indices,
            });
        }
    }
    Ok(fields)
}

fn exact_field_rva_bytes(
    image: &[u8],
    view: &ImageView,
    resolver: &Resolver,
    metadata_index: &ReactorMetadataIndex,
    field_token: u32,
) -> Option<Vec<u8>> {
    if token_table(field_token) != Some(TableId::Field) {
        return None;
    }
    let field_rid: u32 = field_token & 0x00FF_FFFF;
    let field: &FieldRow = resolver.tables().fields.get(row_index(field_rid)?)?;
    let allowed_field_flags: u16 = REACTOR_FIELD_ACCESS_MASK
        | REACTOR_FIELD_STATIC
        | REACTOR_FIELD_INIT_ONLY
        | REACTOR_FIELD_HAS_RVA
        | REACTOR_FIELD_SPECIAL_NAME
        | REACTOR_FIELD_RT_SPECIAL_NAME;
    if field.flags & (REACTOR_FIELD_STATIC | REACTOR_FIELD_HAS_RVA)
        != (REACTOR_FIELD_STATIC | REACTOR_FIELD_HAS_RVA)
        || field.flags & !allowed_field_flags != 0
        || field.flags & REACTOR_FIELD_ACCESS_MASK == REACTOR_FIELD_ACCESS_MASK
        || (field.flags & REACTOR_FIELD_RT_SPECIAL_NAME != 0
            && field.flags & REACTOR_FIELD_SPECIAL_NAME == 0)
    {
        return None;
    }
    let field_type: TypeSig = parse_field_sig_strict(resolver.blob(field.signature)?).ok()?;
    let TypeSig::NamedType {
        is_value_type: true,
        token: layout_token,
    } = field_type
    else {
        return None;
    };
    if token_table(layout_token) != Some(TableId::TypeDef) {
        return None;
    }
    let layout_rid: u32 = layout_token & 0x00FF_FFFF;
    let layout_type: &crate::tables::TypeDefRow =
        resolver.tables().type_defs.get(row_index(layout_rid)?)?;
    if layout_type.flags & REACTOR_TYPE_LAYOUT_MASK != REACTOR_TYPE_EXPLICIT_LAYOUT
        || layout_type.flags & REACTOR_TYPE_INTERFACE != 0
        || layout_type.flags & REACTOR_TYPE_SEALED == 0
        || !layout_type.extends.is_some_and(|extends: RowRef| {
            row_ref_token(extends).is_some_and(|token: u32| {
                framework_type_matches(resolver, token, "System", "ValueType")
            })
        })
        || metadata_index.generic_type_owners.contains(&layout_rid)
        || !metadata_index.fieldless_types.contains(&layout_rid)
    {
        return None;
    }
    let layout: crate::tables::ClassLayoutRow = metadata_index
        .class_layouts
        .get(&layout_rid)
        .copied()
        .flatten()?;
    if layout.packing_size != 1 || !matches!(layout.class_size, 16 | 32) {
        return None;
    }
    let rva: FieldRvaRow = metadata_index
        .field_rvas
        .get(&field_rid)
        .copied()
        .flatten()?;
    let size: usize = usize::try_from(layout.class_size).ok()?;
    let size_u32: u32 = u32::try_from(size).ok()?;
    let data_end: u32 = rva.rva.checked_add(size_u32)?;
    let metadata_end: u32 = view.clr.metadata.rva.checked_add(view.clr.metadata.size)?;
    if rva.rva == 0
        || size > MAX_RESOURCE_BYTES
        || (rva.rva < metadata_end && view.clr.metadata.rva < data_end)
    {
        return None;
    }
    let offset: usize = exact_file_backed_rva_offset(image, &view.pe, rva.rva, size)?;
    image
        .get(offset..offset.checked_add(size)?)
        .map(<[u8]>::to_vec)
}

fn exact_file_backed_rva_offset(image: &[u8], pe: &PeImage, rva: u32, len: usize) -> Option<usize> {
    let bytes: &[u8] = pe.slice_exact_file_backed_rva(image, rva, len)?;
    (bytes.as_ptr() as usize).checked_sub(image.as_ptr() as usize)
}

fn recover_reactor_candidate(
    image: &[u8],
    view: &ImageView,
    candidate: ReactorCandidate,
) -> ResourceStringRecovery {
    let resource: Option<&[u8]> =
        unique_embedded_resource(image, view, &candidate.provenance.resource_name);
    let resource_size: u32 = resource
        .and_then(|bytes: &[u8]| u32::try_from(bytes.len()).ok())
        .unwrap_or(0);
    let mut recovery: ResourceStringRecovery = ResourceStringRecovery {
        resource_name: candidate.provenance.resource_name.clone(),
        resource_size,
        scheme: format!(
            "Reactor v4 static AES-256-CBC resource (CIL-bound FieldRVA key/IV{}), strict Int32-length-prefixed UTF-16 record stream",
            if candidate.provenance.reverse_iv {
                ", reversed IV"
            } else {
                ""
            }
        ),
        strings: Vec::new(),
        dynamic_wall: None,
    };
    let Some(ciphertext): Option<&[u8]> = resource else {
        recovery.dynamic_wall = Some(
            "Unknown: Reactor structurally selected resource is absent or duplicated".to_string(),
        );
        return recovery;
    };
    let mut iv: [u8; 16] = candidate.iv;
    if candidate.provenance.reverse_iv {
        iv.reverse();
    }
    let plaintext: Vec<u8> = match disrobe_core::codec::aes_cbc_decrypt(
        &candidate.key,
        &iv,
        ciphertext,
        disrobe_core::codec::CbcPadding::Pkcs7,
    ) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            recovery.dynamic_wall = Some(format!(
                "Unknown: Reactor AES-256-CBC resource rejected: {error}"
            ));
            return recovery;
        }
    };
    match read_unicode_records_int32_strict(&plaintext) {
        Some(strings) => recovery.strings = strings,
        None => {
            recovery.dynamic_wall = Some(
                "Unknown: Reactor plaintext is not a complete strict Int32-length-prefixed UTF-16 record stream"
                    .to_string(),
            );
        }
    }
    recovery
}

fn reactor_unknown(view: &ImageView, reason: String) -> ResourceStringRecovery {
    let row: Option<&ManifestResourceRow> = first_resource(view);
    ResourceStringRecovery {
        resource_name: row
            .and_then(|resource: &ManifestResourceRow| string_at(&view.strings, resource.name))
            .unwrap_or_default(),
        resource_size: 0,
        scheme: "Reactor static string resource".to_string(),
        strings: Vec::new(),
        dynamic_wall: Some(reason),
    }
}

fn embedded_resource_names(view: &ImageView) -> BTreeSet<String> {
    view.tables
        .manifest_resources
        .iter()
        .filter(|row: &&ManifestResourceRow| row.implementation.is_none())
        .filter_map(|row: &ManifestResourceRow| string_at(&view.strings, row.name))
        .filter(|name: &String| !name.is_empty())
        .collect()
}

fn unique_embedded_resource<'a>(image: &'a [u8], view: &ImageView, name: &str) -> Option<&'a [u8]> {
    let rows: Vec<&ManifestResourceRow> = view
        .tables
        .manifest_resources
        .iter()
        .filter(|row: &&ManifestResourceRow| {
            row.implementation.is_none()
                && string_at(&view.strings, row.name).as_deref() == Some(name)
        })
        .collect();
    let [row]: [&ManifestResourceRow; 1] = rows.try_into().ok()?;
    embedded_resource_bytes(image, view, row)
}

fn unique_framework_call(
    resolver: &Resolver,
    body: &MethodBody,
    flow: &ReactorFlow,
    namespace: &str,
    type_name: &str,
    member_name: &str,
    shape: ReactorCallShape,
) -> std::result::Result<usize, String> {
    let calls: Vec<(usize, &Instruction)> =
        framework_calls(resolver, body, flow, namespace, type_name, member_name);
    if calls.len() != 1 {
        return Err(format!(
            "Unknown: Reactor {namespace}.{type_name}::{member_name} has {} reachable calls",
            calls.len()
        ));
    }
    let (index, instruction): (usize, &Instruction) = calls[0];
    if !call_shape_matches(resolver, instruction, shape) {
        return Err(format!(
            "Unknown: Reactor {namespace}.{type_name}::{member_name} signature is unsupported"
        ));
    }
    Ok(index)
}

fn stored_call_result(
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
    label: &str,
) -> std::result::Result<LocalBinding, String> {
    let store_index: usize = call_index
        .checked_add(1)
        .filter(|index: &usize| *index < body.instructions.len())
        .ok_or_else(|| format!("Unknown: Reactor {label} result store is absent"))?;
    if !flow.has_edge(call_index, store_index) || !flow.dominates(call_index, store_index) {
        return Err(format!(
            "Unknown: Reactor {label} result store is not uniquely reached from its producer"
        ));
    }
    let local: u16 = body
        .instructions
        .get(store_index)
        .and_then(local_store_index)
        .ok_or_else(|| format!("Unknown: Reactor {label} result is not stored in a local"))?;
    Ok(LocalBinding {
        local,
        producer_index: call_index,
        store_index,
    })
}

fn framework_calls<'a>(
    resolver: &Resolver,
    body: &'a MethodBody,
    flow: &ReactorFlow,
    namespace: &str,
    type_name: &str,
    member_name: &str,
) -> Vec<(usize, &'a Instruction)> {
    body.instructions
        .iter()
        .enumerate()
        .filter(|(index, instruction): &(usize, &Instruction)| {
            flow.is_reachable(*index)
                && instruction_calls_framework_member(
                    resolver,
                    instruction,
                    namespace,
                    type_name,
                    member_name,
                )
        })
        .collect()
}

fn instruction_matches_framework_call(
    resolver: &Resolver,
    instruction: &Instruction,
    namespace: &str,
    type_name: &str,
    member_name: &str,
    shape: ReactorCallShape,
) -> bool {
    instruction_calls_framework_member(resolver, instruction, namespace, type_name, member_name)
        && call_shape_matches(resolver, instruction, shape)
}

pub(super) fn call_shape_matches(
    resolver: &Resolver,
    instruction: &Instruction,
    shape: ReactorCallShape,
) -> bool {
    let Some(token): Option<u32> = instruction_call_token(instruction) else {
        return false;
    };
    let opcode_valid: bool = match shape {
        ReactorCallShape::AesCreate
        | ReactorCallShape::GetExecutingAssembly
        | ReactorCallShape::InitializeArray
        | ReactorCallShape::BitConverterToInt32
        | ReactorCallShape::EncodingUnicode
        | ReactorCallShape::ReverseArray => instruction.name == "call",
        ReactorCallShape::CryptoStreamConstructor
        | ReactorCallShape::MemoryStreamConstructor
        | ReactorCallShape::InvalidDataExceptionConstructor => instruction.name == "newobj",
        ReactorCallShape::CreateDecryptor
        | ReactorCallShape::SetCipherMode
        | ReactorCallShape::SetPaddingMode
        | ReactorCallShape::SetByteArray
        | ReactorCallShape::GetManifestResourceStream
        | ReactorCallShape::StreamCopyTo
        | ReactorCallShape::MemoryStreamToArray
        | ReactorCallShape::EncodingGetString => {
            matches!(instruction.name.as_str(), "call" | "callvirt")
        }
        ReactorCallShape::Dispose => instruction.name == "callvirt",
    };
    if !opcode_valid {
        return false;
    }
    let Some((member_token, instantiation)): Option<(u32, Option<Vec<TypeSig>>)> =
        framework_call_target(resolver, token)
    else {
        return false;
    };
    if shape != ReactorCallShape::ReverseArray && instantiation.is_some() {
        return false;
    }
    let Some(signature): Option<crate::signature::MethodSig> =
        strict_member_signature(resolver, member_token)
    else {
        return false;
    };
    let expected_calling_convention: u8 = crate::signature::SIG_DEFAULT
        | if signature.has_this {
            crate::signature::SIG_HASTHIS
        } else {
            0
        }
        | if signature.generic_param_count != 0 {
            crate::signature::SIG_GENERIC
        } else {
            0
        };
    if signature.calling_convention != expected_calling_convention || signature.explicit_this {
        return false;
    }
    match shape {
        ReactorCallShape::AesCreate => {
            !signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && return_named_type(
                    resolver,
                    &signature.return_type,
                    false,
                    "System.Security.Cryptography",
                    "Aes",
                )
        }
        ReactorCallShape::CreateDecryptor => {
            signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && return_named_type(
                    resolver,
                    &signature.return_type,
                    false,
                    "System.Security.Cryptography",
                    "ICryptoTransform",
                )
        }
        ReactorCallShape::SetCipherMode => {
            signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 1
                && named_type(
                    resolver,
                    &signature.params[0],
                    true,
                    "System.Security.Cryptography",
                    "CipherMode",
                )
        }
        ReactorCallShape::SetPaddingMode => {
            signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 1
                && named_type(
                    resolver,
                    &signature.params[0],
                    true,
                    "System.Security.Cryptography",
                    "PaddingMode",
                )
        }
        ReactorCallShape::SetByteArray => {
            signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.as_slice() == [TypeSig::SzArray(Box::new(TypeSig::U1))]
        }
        ReactorCallShape::GetExecutingAssembly => {
            !signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && return_named_type(
                    resolver,
                    &signature.return_type,
                    false,
                    "System.Reflection",
                    "Assembly",
                )
        }
        ReactorCallShape::GetManifestResourceStream => {
            signature.has_this
                && signature.generic_param_count == 0
                && signature.params.as_slice() == [TypeSig::String]
                && return_named_type(
                    resolver,
                    &signature.return_type,
                    false,
                    "System.IO",
                    "Stream",
                )
        }
        ReactorCallShape::InitializeArray => {
            !signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 2
                && named_type(resolver, &signature.params[0], false, "System", "Array")
                && named_type(
                    resolver,
                    &signature.params[1],
                    true,
                    "System",
                    "RuntimeFieldHandle",
                )
        }
        ReactorCallShape::ReverseArray => {
            !signature.has_this
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 1
                && match (signature.generic_param_count, instantiation.as_deref()) {
                    (0, None) => {
                        named_type(resolver, &signature.params[0], false, "System", "Array")
                    }
                    (1, Some([TypeSig::U1])) => {
                        signature.params[0] == TypeSig::SzArray(Box::new(TypeSig::MVar(0)))
                    }
                    _ => false,
                }
        }
        ReactorCallShape::CryptoStreamConstructor => {
            instruction.name == "newobj"
                && signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 3
                && named_type(resolver, &signature.params[0], false, "System.IO", "Stream")
                && named_type(
                    resolver,
                    &signature.params[1],
                    false,
                    "System.Security.Cryptography",
                    "ICryptoTransform",
                )
                && named_type(
                    resolver,
                    &signature.params[2],
                    true,
                    "System.Security.Cryptography",
                    "CryptoStreamMode",
                )
        }
        ReactorCallShape::MemoryStreamConstructor => {
            instruction.name == "newobj"
                && signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.is_empty()
        }
        ReactorCallShape::InvalidDataExceptionConstructor => {
            signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.as_slice() == [TypeSig::String]
        }
        ReactorCallShape::StreamCopyTo => {
            signature.has_this
                && signature.generic_param_count == 0
                && matches!(signature.return_type, TypeSigOrVoid::Void)
                && signature.params.len() == 1
                && named_type(resolver, &signature.params[0], false, "System.IO", "Stream")
        }
        ReactorCallShape::MemoryStreamToArray => {
            signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && matches!(
                    signature.return_type,
                    TypeSigOrVoid::Type(TypeSig::SzArray(ref element)) if **element == TypeSig::U1
                )
        }
        ReactorCallShape::Dispose => {
            signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && matches!(signature.return_type, TypeSigOrVoid::Void)
        }
        ReactorCallShape::BitConverterToInt32 => {
            !signature.has_this
                && signature.generic_param_count == 0
                && signature.params.as_slice()
                    == [TypeSig::SzArray(Box::new(TypeSig::U1)), TypeSig::I4]
                && matches!(signature.return_type, TypeSigOrVoid::Type(TypeSig::I4))
        }
        ReactorCallShape::EncodingUnicode => {
            !signature.has_this
                && signature.generic_param_count == 0
                && signature.params.is_empty()
                && return_named_type(
                    resolver,
                    &signature.return_type,
                    false,
                    "System.Text",
                    "Encoding",
                )
        }
        ReactorCallShape::EncodingGetString => {
            signature.has_this
                && signature.generic_param_count == 0
                && signature.params.as_slice()
                    == [
                        TypeSig::SzArray(Box::new(TypeSig::U1)),
                        TypeSig::I4,
                        TypeSig::I4,
                    ]
                && matches!(signature.return_type, TypeSigOrVoid::Type(TypeSig::String))
        }
    }
}

fn strict_member_signature(
    resolver: &Resolver,
    member_token: u32,
) -> Option<crate::signature::MethodSig> {
    if token_table(member_token) != Some(TableId::MemberRef) {
        return None;
    }
    let rid: u32 = member_token & 0x00FF_FFFF;
    let row = resolver.tables().member_refs.get(row_index(rid)?)?;
    parse_method_sig_strict(resolver.blob(row.signature)?).ok()
}

fn framework_call_target(resolver: &Resolver, token: u32) -> Option<(u32, Option<Vec<TypeSig>>)> {
    match token_table(token)? {
        TableId::MemberRef => Some((token, None)),
        TableId::MethodSpec => {
            let rid: u32 = token & 0x00FF_FFFF;
            let row = resolver.tables().method_specs.get(row_index(rid)?)?;
            let member: RowRef = row.method?;
            if member.table != TableId::MemberRef || member.row == 0 {
                return None;
            }
            let arguments: Vec<TypeSig> =
                parse_method_spec_sig_strict(resolver.blob(row.instantiation)?).ok()?;
            Some((row_ref_token(member)?, Some(arguments)))
        }
        _ => None,
    }
}

fn is_reactor_resource_helper(resolver: &Resolver, method: &MethodModel) -> bool {
    is_managed_cil_method(method)
        && method_signature_is_strict(resolver, method)
        && method.is_static()
        && method.signature.params.is_empty()
        && matches!(
            &method.signature.return_type,
            TypeSigOrVoid::Type(TypeSig::SzArray(element)) if **element == TypeSig::U1
        )
}

fn require_enum_assignment(
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
    receiver_local: u16,
    value: i64,
    label: &str,
) -> std::result::Result<(), String> {
    let receiver_index: usize = prior_index(call_index, 2, label)?;
    let value_index: usize = prior_index(call_index, 1, label)?;
    if !contiguous_dominating(flow, &[receiver_index, value_index, call_index])
        || body
            .instructions
            .get(receiver_index)
            .and_then(local_load_index)
            != Some(receiver_local)
        || body.instructions.get(value_index).and_then(int_literal) != Some(value)
    {
        return Err(format!(
            "Unknown: Reactor {label} is not assigned to the selected AES local"
        ));
    }
    Ok(())
}

fn require_local_assignment(
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
    receiver_local: u16,
    value_local: u16,
    label: &str,
) -> std::result::Result<(), String> {
    let receiver_index: usize = prior_index(call_index, 2, label)?;
    let value_index: usize = prior_index(call_index, 1, label)?;
    if !contiguous_dominating(flow, &[receiver_index, value_index, call_index])
        || body
            .instructions
            .get(receiver_index)
            .and_then(local_load_index)
            != Some(receiver_local)
        || body
            .instructions
            .get(value_index)
            .and_then(local_load_index)
            != Some(value_local)
    {
        return Err(format!(
            "Unknown: Reactor {label} does not bind the selected locals"
        ));
    }
    Ok(())
}

fn require_single_local_argument(
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
    local: u16,
) -> bool {
    let Some(load_index): Option<usize> = call_index.checked_sub(1) else {
        return false;
    };
    contiguous_dominating(flow, &[load_index, call_index])
        && body.instructions.get(load_index).and_then(local_load_index) == Some(local)
}

fn resource_binding(
    resolver: &Resolver,
    body: &MethodBody,
    flow: &ReactorFlow,
) -> std::result::Result<ResourceBinding, String> {
    let assembly_call: usize = unique_framework_call(
        resolver,
        body,
        flow,
        "System.Reflection",
        "Assembly",
        "GetExecutingAssembly",
        ReactorCallShape::GetExecutingAssembly,
    )?;
    let resource_call: usize = unique_framework_call(
        resolver,
        body,
        flow,
        "System.Reflection",
        "Assembly",
        "GetManifestResourceStream",
        ReactorCallShape::GetManifestResourceStream,
    )?;
    let expected_assembly: usize = prior_index(resource_call, 2, "resource lookup")?;
    let string_index: usize = prior_index(resource_call, 1, "resource lookup")?;
    if assembly_call != expected_assembly
        || !contiguous_dominating(flow, &[assembly_call, string_index, resource_call])
    {
        return Err(
            "Unknown: Reactor resource stream is not loaded from the executing assembly"
                .to_string(),
        );
    }
    let load_string: &Instruction = body
        .instructions
        .get(string_index)
        .ok_or_else(|| "Unknown: Reactor resource name instruction is absent".to_string())?;
    let OperandValue::Token(string_token): &OperandValue = &load_string.operand else {
        return Err("Unknown: Reactor resource name is not a user string".to_string());
    };
    if load_string.name != "ldstr" || string_token >> 24 != 0x70 {
        return Err("Unknown: Reactor resource name is not a direct ldstr".to_string());
    }
    let name: String = resolver
        .user_string_strict(string_token & 0x00FF_FFFF)
        .filter(|value: &String| !value.is_empty())
        .ok_or_else(|| "Unknown: Reactor resource name is invalid".to_string())?;
    let (local, store_index): (u16, usize) =
        resource_result_store(resolver, body, flow, resource_call)?;
    let mut instruction_indices: Vec<usize> =
        vec![assembly_call, string_index, resource_call, store_index];
    let direct_store: usize = resource_call
        .checked_add(1)
        .ok_or_else(|| "Unknown: Reactor resource binding index overflowed".to_string())?;
    if store_index != direct_store {
        let branch_index: usize = resource_call
            .checked_add(2)
            .ok_or_else(|| "Unknown: Reactor resource guard index overflowed".to_string())?;
        let failure_index: usize = branch_index
            .checked_add(1)
            .ok_or_else(|| "Unknown: Reactor resource failure index overflowed".to_string())?;
        let throw_index: usize = failure_index
            .checked_add(3)
            .ok_or_else(|| "Unknown: Reactor resource throw index overflowed".to_string())?;
        instruction_indices.extend([
            direct_store,
            branch_index,
            failure_index,
            failure_index + 1,
            failure_index + 2,
            throw_index,
        ]);
    }
    Ok(ResourceBinding {
        name,
        local,
        call_index: resource_call,
        store_index,
        instruction_indices,
    })
}

pub(super) fn resource_result_store(
    resolver: &Resolver,
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
) -> std::result::Result<(u16, usize), String> {
    let direct_store: usize = call_index
        .checked_add(1)
        .ok_or_else(|| "Unknown: Reactor resource store index overflowed".to_string())?;
    if contiguous_dominating(flow, &[call_index, direct_store])
        && let Some(local) = body
            .instructions
            .get(direct_store)
            .and_then(local_store_index)
    {
        return Ok((local, direct_store));
    }
    let duplicate_index: usize = direct_store;
    let branch_index: usize = call_index
        .checked_add(2)
        .ok_or_else(|| "Unknown: Reactor resource guard index overflowed".to_string())?;
    if !contiguous_dominating(flow, &[call_index, duplicate_index, branch_index])
        || body
            .instructions
            .get(duplicate_index)
            .is_none_or(|instruction: &Instruction| instruction.name != "dup")
        || body
            .instructions
            .get(branch_index)
            .is_none_or(|instruction: &Instruction| {
                !matches!(instruction.name.as_str(), "brtrue" | "brtrue.s")
            })
    {
        return Err("Unknown: Reactor resource result has no supported local binding".to_string());
    }
    let successors: &[usize] = flow
        .successors
        .get(branch_index)
        .map(Vec::as_slice)
        .ok_or_else(|| "Unknown: Reactor resource guard successors are absent".to_string())?;
    let [store_index, failure_index]: [usize; 2] = successors.try_into().map_err(|_| {
        "Unknown: Reactor resource guard is not one target and one fallthrough".to_string()
    })?;
    let expected_fallthrough: usize = branch_index
        .checked_add(1)
        .ok_or_else(|| "Unknown: Reactor resource guard fallthrough overflowed".to_string())?;
    if failure_index != expected_fallthrough {
        return Err("Unknown: Reactor resource guard is not binary".to_string());
    }
    if !flow.dominates(branch_index, store_index) || !flow.dominates(branch_index, failure_index) {
        return Err(
            "Unknown: Reactor resource guard targets have alternate predecessors".to_string(),
        );
    }
    let local: u16 = body
        .instructions
        .get(store_index)
        .and_then(local_store_index)
        .ok_or_else(|| {
            "Unknown: Reactor resource guard target does not store the non-null stream".to_string()
        })?;
    if body
        .instructions
        .get(failure_index)
        .is_none_or(|instruction: &Instruction| instruction.name != "pop")
        || !resource_failure_throws(resolver, body, flow, failure_index, store_index)
    {
        return Err("Unknown: Reactor resource null guard is unsupported".to_string());
    }
    Ok((local, store_index))
}

fn resource_failure_throws(
    resolver: &Resolver,
    body: &MethodBody,
    flow: &ReactorFlow,
    start: usize,
    excluded: usize,
) -> bool {
    let Some(message_index): Option<usize> = start.checked_add(1) else {
        return false;
    };
    let Some(constructor_index): Option<usize> = start.checked_add(2) else {
        return false;
    };
    let Some(throw_index): Option<usize> = start.checked_add(3) else {
        return false;
    };
    let Some(message): Option<&Instruction> = body.instructions.get(message_index) else {
        return false;
    };
    let Some(constructor): Option<&Instruction> = body.instructions.get(constructor_index) else {
        return false;
    };
    let Some(throw): Option<&Instruction> = body.instructions.get(throw_index) else {
        return false;
    };
    let OperandValue::Token(message_token): &OperandValue = &message.operand else {
        return false;
    };
    contiguous_dominating(
        flow,
        &[start, message_index, constructor_index, throw_index],
    ) && throw_index.checked_add(1) == Some(excluded)
        && message.name == "ldstr"
        && message_token >> 24 == 0x70
        && resolver
            .user_string_strict(message_token & 0x00FF_FFFF)
            .is_some_and(|value: String| !value.is_empty())
        && instruction_matches_framework_call(
            resolver,
            constructor,
            "System.IO",
            "InvalidDataException",
            ".ctor",
            ReactorCallShape::InvalidDataExceptionConstructor,
        )
        && throw.name == "throw"
        && throw.flow == FlowControl::Throw
        && flow
            .successors
            .get(throw_index)
            .is_some_and(|successors: &Vec<usize>| successors.is_empty())
}

fn require_crypto_stream_arguments(
    body: &MethodBody,
    flow: &ReactorFlow,
    call_index: usize,
    stream_local: u16,
    transform_local: u16,
) -> std::result::Result<(), String> {
    let stream_index: usize = prior_index(call_index, 3, "CryptoStream constructor")?;
    let transform_index: usize = prior_index(call_index, 2, "CryptoStream constructor")?;
    let mode_index: usize = prior_index(call_index, 1, "CryptoStream constructor")?;
    if !contiguous_dominating(
        flow,
        &[stream_index, transform_index, mode_index, call_index],
    ) || body
        .instructions
        .get(stream_index)
        .and_then(local_load_index)
        != Some(stream_local)
        || body
            .instructions
            .get(transform_index)
            .and_then(local_load_index)
            != Some(transform_local)
        || body.instructions.get(mode_index).and_then(int_literal) != Some(0)
    {
        return Err(
            "Unknown: Reactor CryptoStream does not bind the selected resource and decryptor"
                .to_string(),
        );
    }
    Ok(())
}

fn nop_separated_dominating(
    body: &MethodBody,
    flow: &ReactorFlow,
    semantic_indices: &[usize],
) -> bool {
    let Some(first): Option<usize> = semantic_indices.first().copied() else {
        return false;
    };
    let Some(last): Option<usize> = semantic_indices.last().copied() else {
        return false;
    };
    if semantic_indices
        .windows(2)
        .any(|pair: &[usize]| pair[0] >= pair[1])
    {
        return false;
    }
    let full_indices: Vec<usize> = (first..=last).collect();
    contiguous_dominating(flow, &full_indices)
        && full_indices.iter().all(|index: &usize| {
            semantic_indices.binary_search(index).is_ok()
                || body
                    .instructions
                    .get(*index)
                    .is_some_and(|instruction: &Instruction| instruction.name == "nop")
        })
}

fn exact_local_return_tail(
    body: &MethodBody,
    flow: &ReactorFlow,
    result: &LocalBinding,
) -> std::result::Result<usize, String> {
    let semantic_tail: Vec<usize> = body
        .instructions
        .iter()
        .enumerate()
        .filter(|(index, instruction): &(usize, &Instruction)| {
            *index > result.store_index && flow.is_reachable(*index) && instruction.name != "nop"
        })
        .map(|(index, _): (usize, &Instruction)| index)
        .collect();
    let (load_index, return_index): (usize, usize) = match semantic_tail.as_slice() {
        [load, ret] => (*load, *ret),
        [branch, load, ret]
            if body
                .instructions
                .get(*branch)
                .is_some_and(|instruction: &Instruction| {
                    matches!(instruction.name.as_str(), "br" | "br.s")
                })
                && flow.has_edge(*branch, *load) =>
        {
            (*load, *ret)
        }
        _ => {
            return Err("Unknown: Reactor plaintext return tail is unsupported".to_string());
        }
    };
    if body.instructions.get(load_index).and_then(local_load_index) != Some(result.local)
        || body
            .instructions
            .get(return_index)
            .is_none_or(|instruction: &Instruction| instruction.name != "ret")
        || !flow.dominates(result.store_index, load_index)
        || !flow.dominates(load_index, return_index)
    {
        return Err("Unknown: Reactor plaintext return local is unproven".to_string());
    }
    let reachable_returns: Vec<usize> = body
        .instructions
        .iter()
        .enumerate()
        .filter(|(index, instruction): &(usize, &Instruction)| {
            flow.is_reachable(*index) && instruction.name == "ret"
        })
        .map(|(index, _): (usize, &Instruction)| index)
        .collect();
    if reachable_returns.as_slice() != [return_index] {
        return Err("Unknown: Reactor helper does not have one selected return".to_string());
    }
    Ok(return_index)
}

fn validate_local_provenance(
    body: &MethodBody,
    flow: &ReactorFlow,
    local: u16,
    expected_store: usize,
    expected_loads: &[usize],
    label: &str,
) -> std::result::Result<(), String> {
    let stores: Vec<usize> = body
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction): &(usize, &Instruction)| {
            local_store_index(instruction) == Some(local)
        })
        .map(|(index, _): (usize, &Instruction)| index)
        .collect();
    let loads: Vec<usize> = body
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction): &(usize, &Instruction)| {
            local_load_index(instruction) == Some(local)
        })
        .map(|(index, _): (usize, &Instruction)| index)
        .collect();
    let has_address: bool = body
        .instructions
        .iter()
        .any(|instruction: &Instruction| local_address_index(instruction) == Some(local));
    let mut expected: Vec<usize> = expected_loads.to_vec();
    expected.sort_unstable();
    if stores.as_slice() != [expected_store]
        || loads != expected
        || has_address
        || !flow.is_reachable(expected_store)
        || expected_loads.iter().any(|index: &usize| {
            !flow.is_reachable(*index) || !flow.dominates(expected_store, *index)
        })
    {
        return Err(format!(
            "Unknown: Reactor {label} local has unproven stores, loads, or aliases"
        ));
    }
    Ok(())
}

pub(super) fn contiguous_dominating(flow: &ReactorFlow, indices: &[usize]) -> bool {
    !indices.is_empty()
        && indices
            .iter()
            .all(|index: &usize| flow.is_reachable(*index))
        && indices
            .windows(2)
            .all(|pair: &[usize]| flow.has_edge(pair[0], pair[1]))
        && indices.last().is_some_and(|last: &usize| {
            indices
                .iter()
                .all(|index: &usize| flow.dominates(*index, *last))
        })
}

fn prior_index(index: usize, distance: usize, label: &str) -> std::result::Result<usize, String> {
    index
        .checked_sub(distance)
        .ok_or_else(|| format!("Unknown: Reactor {label} operand sequence is truncated"))
}

fn return_named_type(
    resolver: &Resolver,
    return_type: &TypeSigOrVoid,
    is_value_type: bool,
    namespace: &str,
    name: &str,
) -> bool {
    let TypeSigOrVoid::Type(signature): &TypeSigOrVoid = return_type else {
        return false;
    };
    named_type(resolver, signature, is_value_type, namespace, name)
}

fn named_type(
    resolver: &Resolver,
    signature: &TypeSig,
    is_value_type: bool,
    namespace: &str,
    name: &str,
) -> bool {
    let TypeSig::NamedType {
        is_value_type: actual_value_type,
        token,
    } = signature
    else {
        return false;
    };
    *actual_value_type == is_value_type && framework_type_matches(resolver, *token, namespace, name)
}

fn framework_type_matches(resolver: &Resolver, token: u32, namespace: &str, name: &str) -> bool {
    if token_table(token) != Some(TableId::TypeRef) {
        return false;
    }
    let rid: u32 = token & 0x00FF_FFFF;
    let Some(type_ref) =
        row_index(rid).and_then(|index: usize| resolver.tables().type_refs.get(index))
    else {
        return false;
    };
    if resolver.string(type_ref.namespace) != namespace || resolver.string(type_ref.name) != name {
        return false;
    }
    let Some(scope): Option<RowRef> = type_ref.resolution_scope else {
        return false;
    };
    if scope.table != TableId::AssemblyRef || scope.row == 0 {
        return false;
    }
    row_index(scope.row)
        .and_then(|index: usize| resolver.tables().assembly_refs.get(index))
        .is_some_and(|assembly| framework_assembly_matches(resolver, assembly, namespace, name))
}

fn framework_assembly_matches(
    resolver: &Resolver,
    assembly: &crate::tables::AssemblyRefRow,
    namespace: &str,
    type_name: &str,
) -> bool {
    if assembly.flags != 0 || assembly.culture != 0 {
        return false;
    }
    let Some(token): Option<&[u8]> = resolver.blob(assembly.public_key_or_token) else {
        return false;
    };
    let name: String = resolver.string(assembly.name);
    if !framework_assembly_name_allowed(namespace, type_name, &name) {
        return false;
    }
    match name.as_str() {
        "System.Security.Cryptography"
        | "System.Security.Cryptography.Algorithms"
        | "System.Security.Cryptography.Primitives"
        | "System.Runtime" => token == [0xB0, 0x3F, 0x5F, 0x7F, 0x11, 0xD5, 0x0A, 0x3A],
        "System.Core" | "mscorlib" => token == [0xB7, 0x7A, 0x5C, 0x56, 0x19, 0x34, 0xE0, 0x89],
        "System.Private.CoreLib" => token == [0x7C, 0xEC, 0x85, 0xD7, 0xBE, 0xA7, 0x79, 0x8E],
        "netstandard" => token == [0xCC, 0x7B, 0x13, 0xFF, 0xCD, 0x2D, 0xDD, 0x51],
        _ => false,
    }
}

pub(super) fn framework_assembly_name_allowed(
    namespace: &str,
    type_name: &str,
    assembly_name: &str,
) -> bool {
    match (namespace, type_name) {
        ("System.Security.Cryptography", "Aes") => matches!(
            assembly_name,
            "System.Security.Cryptography"
                | "System.Security.Cryptography.Algorithms"
                | "System.Core"
                | "mscorlib"
                | "netstandard"
        ),
        (
            "System.Security.Cryptography",
            "SymmetricAlgorithm" | "ICryptoTransform" | "CipherMode" | "PaddingMode"
            | "CryptoStream" | "CryptoStreamMode",
        ) => matches!(
            assembly_name,
            "System.Security.Cryptography"
                | "System.Security.Cryptography.Primitives"
                | "System.Core"
                | "mscorlib"
                | "netstandard"
        ),
        ("System", "Byte" | "Array" | "RuntimeFieldHandle" | "BitConverter" | "ValueType")
        | ("System.IO", "Stream" | "MemoryStream" | "InvalidDataException")
        | ("System.Reflection", "Assembly")
        | ("System.Runtime.CompilerServices", "RuntimeHelpers")
        | ("System.Text", "Encoding") => matches!(
            assembly_name,
            "System.Runtime" | "mscorlib" | "System.Private.CoreLib" | "netstandard"
        ),
        _ => false,
    }
}

pub(super) fn instruction_calls_framework_member(
    resolver: &Resolver,
    instruction: &Instruction,
    namespace: &str,
    type_name: &str,
    member_name: &str,
) -> bool {
    let Some(token): Option<u32> = instruction_call_token(instruction) else {
        return false;
    };
    framework_member_matches(resolver, token, namespace, type_name, member_name)
}

fn instruction_call_token(instruction: &Instruction) -> Option<u32> {
    if !matches!(instruction.name.as_str(), "call" | "callvirt" | "newobj") {
        return None;
    }
    let OperandValue::Token(token): &OperandValue = &instruction.operand else {
        return None;
    };
    Some(*token)
}

fn framework_member_matches(
    resolver: &Resolver,
    token: u32,
    namespace: &str,
    type_name: &str,
    member_name: &str,
) -> bool {
    let Some(member_token): Option<u32> = unwrap_method_spec(resolver, token) else {
        return false;
    };
    if token_table(member_token) != Some(TableId::MemberRef) {
        return false;
    }
    let rid: u32 = member_token & 0x00FF_FFFF;
    let Some(member) =
        row_index(rid).and_then(|index: usize| resolver.tables().member_refs.get(index))
    else {
        return false;
    };
    if resolver.string(member.name) != member_name {
        return false;
    }
    let Some(parent): Option<RowRef> = member.parent else {
        return false;
    };
    row_ref_token(parent)
        .is_some_and(|token: u32| framework_type_matches(resolver, token, namespace, type_name))
}

fn unwrap_method_spec(resolver: &Resolver, token: u32) -> Option<u32> {
    match token_table(token)? {
        TableId::MethodSpec => {
            let rid: u32 = token & 0x00FF_FFFF;
            let method: RowRef = resolver
                .tables()
                .method_specs
                .get(row_index(rid)?)?
                .method?;
            row_ref_token(method)
        }
        TableId::MemberRef => Some(token),
        _ => None,
    }
}

pub(super) fn direct_static_helper_token(
    instruction: &Instruction,
    method_tokens: &BTreeSet<u32>,
) -> Option<u32> {
    if instruction.name != "call" {
        return None;
    }
    let OperandValue::Token(token): &OperandValue = &instruction.operand else {
        return None;
    };
    method_tokens.contains(token).then_some(*token)
}

fn is_reactor_string_entry(resolver: &Resolver, method: &MethodModel) -> bool {
    is_managed_cil_method(method)
        && method_signature_is_strict(resolver, method)
        && method.is_static()
        && method.signature.params.as_slice() == [TypeSig::I4]
        && matches!(
            &method.signature.return_type,
            TypeSigOrVoid::Type(TypeSig::String)
        )
}

const fn is_managed_cil_method(method: &MethodModel) -> bool {
    method.rva != 0
        && method.signature.calling_convention == crate::signature::SIG_DEFAULT
        && !method.signature.has_this
        && !method.signature.explicit_this
        && method.signature.generic_param_count == 0
        && method.flags & (REACTOR_METHOD_ABSTRACT | REACTOR_METHOD_PINVOKE_IMPL) == 0
        && method.impl_flags
            & (REACTOR_METHOD_IMPL_CODE_TYPE_MASK
                | REACTOR_METHOD_IMPL_UNMANAGED
                | REACTOR_METHOD_IMPL_FORWARD_REF
                | REACTOR_METHOD_IMPL_INTERNAL_CALL)
            == 0
}

fn method_signature_is_strict(resolver: &Resolver, method: &MethodModel) -> bool {
    if token_table(method.token) != Some(TableId::MethodDef) {
        return false;
    }
    let rid: u32 = method.token & 0x00FF_FFFF;
    row_index(rid)
        .and_then(|index: usize| resolver.tables().methods.get(index))
        .and_then(|row| resolver.blob(row.signature))
        .and_then(|blob: &[u8]| parse_method_sig_strict(blob).ok())
        .is_some_and(|signature| signature == method.signature)
}

fn method_by_token(ty: &TypeModel, token: u32) -> Option<&MethodModel> {
    ty.methods
        .iter()
        .find(|method: &&MethodModel| method.token == token)
}

pub(super) fn reactor_method_body(
    image: &[u8],
    pe: &PeImage,
    rva: u32,
) -> std::result::Result<MethodBody, String> {
    let offset: usize = pe
        .rva_to_offset(rva)
        .ok_or_else(|| "method RVA is not file-backed".to_string())?;
    let bytes: &[u8] = image
        .get(offset..)
        .ok_or_else(|| "method offset is outside the image".to_string())?;
    let code_size: u32 = method_body_code_size(bytes).map_err(|error| error.to_string())?;
    if code_size > MAX_REACTOR_METHOD_CODE_BYTES {
        return Err(format!(
            "method code size {code_size} exceeds {MAX_REACTOR_METHOD_CODE_BYTES} bytes"
        ));
    }
    let bounded: &[u8] = bytes
        .get(..bytes.len().min(MAX_REACTOR_METHOD_TOTAL_BYTES))
        .ok_or_else(|| "method extent preflight range is invalid".to_string())?;
    let extent: crate::cil::MethodBodyExtent =
        method_body_extent(bounded).map_err(|error| error.to_string())?;
    if extent.consumed_bytes > MAX_REACTOR_METHOD_TOTAL_BYTES {
        return Err(format!(
            "method extent {} exceeds {MAX_REACTOR_METHOD_TOTAL_BYTES} bytes",
            extent.consumed_bytes
        ));
    }
    if exact_file_backed_rva_offset(image, pe, rva, extent.consumed_bytes) != Some(offset) {
        return Err("method body crosses a file-backed RVA range".to_string());
    }
    validate_reactor_method_sections(bounded, extent.consumed_bytes)?;
    let body: MethodBody = parse_method_body(bounded).map_err(|error| error.to_string())?;
    if body.instructions.len() > MAX_REACTOR_METHOD_INSTRUCTIONS {
        return Err(format!(
            "method instruction count {} exceeds {MAX_REACTOR_METHOD_INSTRUCTIONS}",
            body.instructions.len()
        ));
    }
    Ok(body)
}

pub(super) fn validate_reactor_method_sections(
    bytes: &[u8],
    consumed_bytes: usize,
) -> std::result::Result<(), String> {
    let first: u8 = *bytes
        .first()
        .ok_or_else(|| "method header is absent".to_string())?;
    if first & 0x03 == 0x02 {
        return Ok(());
    }
    let flags_bytes: [u8; 2] = bytes
        .get(..2)
        .and_then(|value: &[u8]| value.try_into().ok())
        .ok_or_else(|| "fat method flags are truncated".to_string())?;
    let flags_size: u16 = u16::from_le_bytes(flags_bytes);
    let header_words: u16 = flags_size >> 12;
    let supported_flags: u16 = REACTOR_FAT_METHOD_FORMAT
        | REACTOR_FAT_METHOD_MORE_SECTIONS
        | REACTOR_FAT_METHOD_INIT_LOCALS;
    if header_words != REACTOR_FAT_METHOD_HEADER_WORDS
        || flags_size & 0x0FFF & !supported_flags != 0
        || flags_size & REACTOR_FAT_METHOD_FORMAT != REACTOR_FAT_METHOD_FORMAT
    {
        return Err("fat method header contains unsupported flags or extensions".to_string());
    }
    let header_size: usize = usize::from(flags_size >> 12)
        .checked_mul(4)
        .ok_or_else(|| "fat method header size overflowed".to_string())?;
    let code_size: usize =
        usize::try_from(method_body_code_size(bytes).map_err(|error| error.to_string())?)
            .map_err(|_| "method code size is not addressable".to_string())?;
    let code_end: usize = header_size
        .checked_add(code_size)
        .ok_or_else(|| "method code end overflowed".to_string())?;
    if flags_size & REACTOR_FAT_METHOD_MORE_SECTIONS == 0 {
        return (consumed_bytes == code_end)
            .then_some(())
            .ok_or_else(|| "method extent contains unannounced sections".to_string());
    }
    let mut position: usize = code_end
        .checked_add(3)
        .ok_or_else(|| "method section alignment overflowed".to_string())?
        & !3usize;
    loop {
        let header: &[u8] = bytes
            .get(
                position
                    ..position
                        .checked_add(4)
                        .ok_or_else(|| "method section header overflowed".to_string())?,
            )
            .ok_or_else(|| "method section header is truncated".to_string())?;
        let kind: u8 = header[0];
        if kind & !0xC1 != 0 || kind & 0x01 == 0 {
            return Err("method contains an unsupported data section".to_string());
        }
        let is_fat: bool = kind & 0x40 != 0;
        if !is_fat && (header[2] != 0 || header[3] != 0) {
            return Err("small exception section reserved bytes are nonzero".to_string());
        }
        let data_size: usize = if is_fat {
            usize::from(header[1]) | (usize::from(header[2]) << 8) | (usize::from(header[3]) << 16)
        } else {
            usize::from(header[1])
        };
        let entry_size: usize = if is_fat { 24 } else { 12 };
        let payload_size: usize = data_size
            .checked_sub(4)
            .ok_or_else(|| "exception section is smaller than its header".to_string())?;
        if payload_size == 0 || !payload_size.is_multiple_of(entry_size) {
            return Err("exception section has a partial or empty clause table".to_string());
        }
        let section_end: usize = position
            .checked_add(data_size)
            .ok_or_else(|| "exception section end overflowed".to_string())?;
        let section: &[u8] = bytes
            .get(position..section_end)
            .ok_or_else(|| "exception section is truncated".to_string())?;
        for entry in section[4..].chunks_exact(entry_size) {
            let clause_flags: u32 = if is_fat {
                u32::from_le_bytes(
                    entry
                        .get(..4)
                        .and_then(|value: &[u8]| value.try_into().ok())
                        .ok_or_else(|| "fat exception flags are truncated".to_string())?,
                )
            } else {
                u32::from(u16::from_le_bytes(
                    entry
                        .get(..2)
                        .and_then(|value: &[u8]| value.try_into().ok())
                        .ok_or_else(|| "small exception flags are truncated".to_string())?,
                ))
            };
            if !matches!(clause_flags, 0 | 1 | 2 | 4) {
                return Err("exception clause flags are unsupported".to_string());
            }
        }
        if kind & 0x80 == 0 {
            if section_end != consumed_bytes {
                return Err("method extent contains trailing section bytes".to_string());
            }
            return Ok(());
        }
        position = section_end
            .checked_add(3)
            .ok_or_else(|| "next method section alignment overflowed".to_string())?
            & !3usize;
        if position >= consumed_bytes {
            return Err("method advertises a missing exception section".to_string());
        }
    }
}

fn reactor_local_types(
    resolver: &Resolver,
    body: &MethodBody,
) -> std::result::Result<Vec<TypeSig>, String> {
    let local_types: Vec<TypeSig> = if body.local_var_sig_tok == 0 {
        Vec::new()
    } else {
        if token_table(body.local_var_sig_tok) != Some(TableId::StandAloneSig) {
            return Err("Unknown: Reactor local signature token has the wrong table".to_string());
        }
        let rid: u32 = body.local_var_sig_tok & 0x00FF_FFFF;
        let row = resolver
            .tables()
            .standalone_sigs
            .get(
                row_index(rid)
                    .ok_or_else(|| "Unknown: Reactor local signature row is zero".to_string())?,
            )
            .ok_or_else(|| "Unknown: Reactor local signature row is absent".to_string())?;
        parse_local_sig_strict(
            resolver
                .blob(row.signature)
                .ok_or_else(|| "Unknown: Reactor local signature blob is absent".to_string())?,
        )
        .map_err(|error| format!("Unknown: Reactor local signature is invalid: {error}"))?
    };
    let mut used_locals: Vec<bool> = vec![false; local_types.len()];
    for instruction in &body.instructions {
        let index: Option<u16> = local_load_index(instruction)
            .or_else(|| local_store_index(instruction))
            .or_else(|| local_address_index(instruction));
        if let Some(value) = index {
            let used: &mut bool = used_locals
                .get_mut(usize::from(value))
                .ok_or_else(|| "Unknown: Reactor CIL references an undeclared local".to_string())?;
            *used = true;
        }
    }
    if used_locals.iter().any(|used: &bool| !used) {
        return Err("Unknown: Reactor local signature declares unused locals".to_string());
    }
    Ok(local_types)
}

fn local_load_index(instruction: &Instruction) -> Option<u16> {
    slot_index_of(instruction, SlotOp::LoadLocal)
}

fn local_store_index(instruction: &Instruction) -> Option<u16> {
    slot_index_of(instruction, SlotOp::StoreLocal)
}

fn local_address_index(instruction: &Instruction) -> Option<u16> {
    slot_index_of(instruction, SlotOp::LocalAddress)
}

const fn token_table(token: u32) -> Option<TableId> {
    TableId::from_index(token.to_be_bytes()[0])
}

pub(super) fn row_ref_token(reference: RowRef) -> Option<u32> {
    (reference.row != 0 && reference.row <= 0x00FF_FFFF)
        .then_some((u32::from(reference.table as u8) << 24) | reference.row)
}

fn row_index(rid: u32) -> Option<usize> {
    usize::try_from(rid.checked_sub(1)?).ok()
}
