use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::cluster::DartReadStream;
use super::dart_graph_layout::{DartClusterBodyKind, DartPinnedLayout};
use crate::error::{Error, Result};

const HARD_CLUSTER_LIMIT: usize = 4096;
const HARD_OBJECT_LIMIT: usize = 2_000_000;
const HARD_REFERENCE_LIMIT: usize = 16_000_000;
const HARD_STRING_CODE_UNIT_LIMIT: usize = 16 * 1024 * 1024;
const HARD_TOTAL_STRING_BYTE_LIMIT: usize = 256 * 1024 * 1024;
const HARD_VARIABLE_LENGTH_LIMIT: usize = 64 * 1024 * 1024;

const MINT_CLASS_ID: i32 = 61;

const MAX_POOL_SLOTS: usize = 1 << 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphLimits {
    pub clusters: usize,
    pub objects: usize,
    pub references: usize,
    pub string_code_units: usize,
    pub total_string_bytes: usize,
    pub variable_length: usize,
}

impl Default for DartGraphLimits {
    fn default() -> Self {
        Self {
            clusters: HARD_CLUSTER_LIMIT,
            objects: HARD_OBJECT_LIMIT,
            references: HARD_REFERENCE_LIMIT,
            string_code_units: HARD_STRING_CODE_UNIT_LIMIT,
            total_string_bytes: HARD_TOTAL_STRING_BYTE_LIMIT,
            variable_length: HARD_VARIABLE_LENGTH_LIMIT,
        }
    }
}

impl DartGraphLimits {
    pub(super) fn validate(self) -> Result<()> {
        validate_limit("configured clusters", self.clusters, HARD_CLUSTER_LIMIT)?;
        validate_limit("configured objects", self.objects, HARD_OBJECT_LIMIT)?;
        validate_limit(
            "configured references",
            self.references,
            HARD_REFERENCE_LIMIT,
        )?;
        validate_limit(
            "configured string code units",
            self.string_code_units,
            HARD_STRING_CODE_UNIT_LIMIT,
        )?;
        validate_limit(
            "configured total string bytes",
            self.total_string_bytes,
            HARD_TOTAL_STRING_BYTE_LIMIT,
        )?;
        validate_limit(
            "configured variable length",
            self.variable_length,
            HARD_VARIABLE_LENGTH_LIMIT,
        )?;
        Ok(())
    }
}

const fn validate_limit(resource: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        return Err(Error::DartGraphConfiguredLimitExceeded {
            resource,
            actual,
            limit,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartGraphSnapshotRole {
    Vm,
    Isolate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum DartGraphNodeKind {
    #[default]
    Unknown,
    Class,
    PatchClass,
    Function,
    Field,
    Library,
    String,
    FunctionType,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartPoolSlot {
    Immediate(i64),
    Object(u32),
    NativeFunction,
    Unmodelled,
}

#[derive(Debug, Clone, Default)]
pub(super) struct DartGraphNode {
    pub(super) kind: DartGraphNodeKind,
    pub(super) references: Vec<u32>,
    pub(super) text: Option<String>,
    pub(super) class_id: Option<i32>,
    pub(super) parameter_count: Option<usize>,
    pub(super) immediate: Option<i64>,
    pub(super) pool_slots: Vec<DartPoolSlot>,
    pub(super) text_is_escaped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphClusterSummary {
    pub index: usize,
    pub class_id: u32,
    pub kind: DartClusterBodyKind,
    pub canonical: bool,
    pub deeply_immutable: bool,
    pub object_count: usize,
    pub first_reference: u32,
    pub allocation_offset: usize,
    pub allocation_bytes: usize,
    pub fill_offset: usize,
    pub fill_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphSnapshotSummary {
    pub base_objects: usize,
    pub total_objects: usize,
    pub cluster_count: usize,
    pub instruction_count: usize,
    pub instruction_table_data_offset: usize,
    pub clustered_offset: usize,
    pub parsed_offset: usize,
    pub clusters: Vec<DartGraphClusterSummary>,
}

#[derive(Debug)]
pub(super) struct DartParsedGraph {
    pub(super) nodes: Vec<DartGraphNode>,
    pub(super) summary: DartGraphSnapshotSummary,
}

#[derive(Debug)]
enum DartGraphAllocation {
    Fixed,
    Lengths(Vec<usize>),
    Class {
        predefined_count: usize,
    },
    Code {
        primary_count: usize,
    },
    Instance {
        next_field_words: usize,
        instance_size_words: usize,
    },
}

#[derive(Debug)]
struct DartGraphCluster {
    index: usize,
    class_id: u32,
    kind: DartClusterBodyKind,
    canonical: bool,
    deeply_immutable: bool,
    start_reference: usize,
    end_reference: usize,
    allocation_offset: usize,
    allocation_end: usize,
    fill_offset: usize,
    fill_end: usize,
    allocation: DartGraphAllocation,
}

struct DartGraphCursor<'data> {
    stream: DartReadStream<'data>,
}

impl<'data> DartGraphCursor<'data> {
    fn new(bytes: &'data [u8], offset: usize) -> Result<Self> {
        let mut stream: DartReadStream<'data> = DartReadStream::new(bytes);
        if stream.skip(offset).is_none() {
            return Err(Error::DartGraphTruncated {
                offset,
                resource: "clustered stream start",
            });
        }
        Ok(Self { stream })
    }

    const fn position(&self) -> usize {
        self.stream.position()
    }

    fn read_u8(&mut self, resource: &'static str) -> Result<u8> {
        let offset: usize = self.position();
        self.stream
            .read_byte()
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_u16(&mut self, resource: &'static str) -> Result<u16> {
        let offset: usize = self.position();
        self.stream
            .read_compact(16)
            .map(|value: u64| value as u16)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_i16(&mut self, resource: &'static str) -> Result<i16> {
        let offset: usize = self.position();
        self.stream
            .read_compact(16)
            .map(|value: u64| value as u16 as i16)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_u32(&mut self, resource: &'static str) -> Result<u32> {
        let offset: usize = self.position();
        self.stream
            .read_compact(32)
            .map(|value: u64| value as u32)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_i32(&mut self, resource: &'static str) -> Result<i32> {
        let offset: usize = self.position();
        self.stream
            .read_compact(32)
            .map(|value: u64| value as u32 as i32)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_i64(&mut self, resource: &'static str) -> Result<i64> {
        let offset: usize = self.position();
        self.stream
            .read_compact(64)
            .map(|value: u64| value as i64)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_unsigned(&mut self, resource: &'static str) -> Result<u64> {
        let offset: usize = self.position();
        self.stream
            .read_unsigned()
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }

    fn read_ref(&mut self, object_count: usize) -> Result<u32> {
        let offset: usize = self.position();
        self.stream
            .read_ref(object_count)
            .ok_or(Error::DartGraphTruncated {
                offset,
                resource: "object reference",
            })
    }

    fn read_bytes(&mut self, length: usize, resource: &'static str) -> Result<&'data [u8]> {
        let offset: usize = self.position();
        self.stream
            .read_bytes(length)
            .ok_or(Error::DartGraphTruncated { offset, resource })
    }
}

struct DartGraphParser<'data> {
    cursor: DartGraphCursor<'data>,
    layout: DartPinnedLayout,
    limits: DartGraphLimits,
    role: DartGraphSnapshotRole,
    object_count: usize,
    nodes: Vec<DartGraphNode>,
    next_reference: usize,
    reference_count: usize,
    total_string_bytes: usize,
}

pub(super) fn parse_dart_graph(
    bytes: &[u8],
    declared_length: usize,
    clustered_offset: usize,
    role: DartGraphSnapshotRole,
    base_nodes: Option<&[DartGraphNode]>,
    layout: DartPinnedLayout,
    limits: DartGraphLimits,
) -> Result<DartParsedGraph> {
    let declared: &[u8] =
        bytes
            .get(..declared_length)
            .ok_or(Error::DartGraphDeclaredLengthOutOfBounds {
                declared: declared_length,
                available: bytes.len(),
            })?;
    let mut cursor: DartGraphCursor<'_> = DartGraphCursor::new(declared, clustered_offset)?;
    let base_objects_raw: u64 = cursor.read_unsigned("base objects")?;
    let base_objects: usize = to_usize(
        base_objects_raw,
        "base objects",
        limits.objects,
        cursor.position(),
    )?;
    let total_objects_raw: u64 = cursor.read_unsigned("objects")?;
    let total_objects: usize = to_usize(
        total_objects_raw,
        "objects",
        limits.objects,
        cursor.position(),
    )?;
    let cluster_count_raw: u64 = cursor.read_unsigned("clusters")?;
    let cluster_count: usize = to_usize(
        cluster_count_raw,
        "clusters",
        limits.clusters,
        cursor.position(),
    )?;
    let instruction_count_raw: u64 = cursor.read_unsigned("instructions")?;
    let instruction_count: usize = to_usize(
        instruction_count_raw,
        "instructions",
        limits.variable_length,
        cursor.position(),
    )?;
    let instruction_table_data_offset_raw: u64 =
        cursor.read_unsigned("instruction table offset")?;
    let instruction_table_data_offset: usize = to_usize(
        instruction_table_data_offset_raw,
        "instruction table offset",
        limits.variable_length,
        cursor.position(),
    )?;
    if base_objects > total_objects {
        return Err(Error::DartGraphInvalidObjectCounts {
            base: base_objects,
            total: total_objects,
        });
    }
    let node_count: usize =
        total_objects
            .checked_add(1)
            .ok_or_else(|| Error::DartGraphLimitExceeded {
                resource: "object nodes",
                offset: cursor.position(),
                actual: usize::MAX,
                limit: limits.objects,
            })?;
    let mut nodes: Vec<DartGraphNode> = Vec::with_capacity(node_count);
    nodes.resize_with(node_count, DartGraphNode::default);
    if let Some(base) = base_nodes {
        let expected: usize = base.len().saturating_sub(1);
        if base_objects != expected {
            return Err(Error::DartGraphBaseObjectMismatch {
                actual: base_objects,
                expected,
            });
        }
        let destination: &mut [DartGraphNode] =
            nodes
                .get_mut(..=base_objects)
                .ok_or(Error::DartGraphInvalidObjectCounts {
                    base: base_objects,
                    total: total_objects,
                })?;
        for (output, source) in destination.iter_mut().zip(base) {
            *output = source.clone();
        }
    }
    let mut parser: DartGraphParser<'_> = DartGraphParser {
        cursor,
        layout,
        limits,
        role,
        object_count: total_objects,
        nodes,
        next_reference: base_objects.saturating_add(1),
        reference_count: 0,
        total_string_bytes: 0,
    };
    let mut clusters: Vec<DartGraphCluster> = Vec::with_capacity(cluster_count);
    for index in 0..cluster_count {
        let cluster: DartGraphCluster = parser.read_allocation(index)?;
        clusters.push(cluster);
    }
    let allocated: usize = parser.next_reference.saturating_sub(1);
    if allocated != total_objects {
        return Err(Error::DartGraphAllocationMismatch {
            index: cluster_count,
            actual: allocated,
            expected: total_objects,
        });
    }
    for output_cluster in &mut clusters {
        let fill_offset: usize = parser.cursor.position();
        parser.read_fill(output_cluster)?;
        output_cluster.fill_offset = fill_offset;
        output_cluster.fill_end = parser.cursor.position();
    }
    let parsed_offset: usize = parser.cursor.position();
    let cluster_summaries: Vec<DartGraphClusterSummary> = clusters
        .into_iter()
        .map(|cluster: DartGraphCluster| DartGraphClusterSummary {
            index: cluster.index,
            class_id: cluster.class_id,
            kind: cluster.kind,
            canonical: cluster.canonical,
            deeply_immutable: cluster.deeply_immutable,
            object_count: cluster
                .end_reference
                .saturating_sub(cluster.start_reference),
            first_reference: u32::try_from(cluster.start_reference).unwrap_or(u32::MAX),
            allocation_offset: cluster.allocation_offset,
            allocation_bytes: cluster
                .allocation_end
                .saturating_sub(cluster.allocation_offset),
            fill_offset: cluster.fill_offset,
            fill_bytes: cluster.fill_end.saturating_sub(cluster.fill_offset),
        })
        .collect();
    Ok(DartParsedGraph {
        nodes: parser.nodes,
        summary: DartGraphSnapshotSummary {
            base_objects,
            total_objects,
            cluster_count,
            instruction_count,
            instruction_table_data_offset,
            clustered_offset,
            parsed_offset,
            clusters: cluster_summaries,
        },
    })
}

impl DartGraphParser<'_> {
    fn read_allocation(&mut self, index: usize) -> Result<DartGraphCluster> {
        let allocation_offset: usize = self.cursor.position();
        let tags: u32 = self.cursor.read_u32("cluster tags")?;
        let class_id: u32 = (tags >> 12) & 0x000f_ffff;
        let canonical: bool = tags & 0x2 != 0;
        let deeply_immutable: bool = tags & 0x80 != 0;
        let kind: DartClusterBodyKind =
            self.layout
                .cluster_body_kind(class_id)
                .ok_or(Error::DartGraphUnsupportedCluster {
                    index,
                    cid: class_id,
                    offset: allocation_offset,
                })?;
        let start_reference: usize = self.next_reference;
        let allocation: DartGraphAllocation = match kind {
            DartClusterBodyKind::Class => self.allocate_classes(index)?,
            DartClusterBodyKind::Code => self.allocate_code(index)?,
            DartClusterBodyKind::Instance => self.allocate_instances(index, class_id)?,
            DartClusterBodyKind::Mint => self.allocate_mints(index)?,
            DartClusterBodyKind::Array
            | DartClusterBodyKind::ObjectPool
            | DartClusterBodyKind::PcDescriptors
            | DartClusterBodyKind::CodeSourceMap
            | DartClusterBodyKind::ExceptionHandlers
            | DartClusterBodyKind::Record
            | DartClusterBodyKind::String
            | DartClusterBodyKind::TypeArguments
            | DartClusterBodyKind::TypedData
            | DartClusterBodyKind::WeakArray => self.allocate_lengths(index, kind, class_id)?,
            _ => self.allocate_fixed(index, kind, class_id)?,
        };
        let end_reference: usize = self.next_reference;
        let count: usize = end_reference.saturating_sub(start_reference);
        if canonical && self.uses_canonical_set(kind) {
            self.read_canonical_layout(index, count)?;
        }
        Ok(DartGraphCluster {
            index,
            class_id,
            kind,
            canonical,
            deeply_immutable,
            start_reference,
            end_reference,
            allocation_offset,
            allocation_end: self.cursor.position(),
            fill_offset: 0,
            fill_end: 0,
            allocation,
        })
    }

    fn allocate_fixed(
        &mut self,
        index: usize,
        kind: DartClusterBodyKind,
        class_id: u32,
    ) -> Result<DartGraphAllocation> {
        let count: usize = self.read_count(index, "object count")?;
        self.assign_nodes(index, count, node_kind(kind), Some(class_id as i32))?;
        Ok(DartGraphAllocation::Fixed)
    }

    fn allocate_classes(&mut self, index: usize) -> Result<DartGraphAllocation> {
        let predefined_count: usize = self.read_count(index, "predefined class count")?;
        for _ in 0..predefined_count {
            let class_id: i32 = self.cursor.read_i32("class id")?;
            if class_id < 0 {
                return Err(Error::DartGraphInvalidClusterValue {
                    index,
                    field: "class id",
                    value: i64::from(class_id),
                    offset: self.cursor.position(),
                });
            }
            self.assign_nodes(index, 1, DartGraphNodeKind::Class, Some(class_id))?;
        }
        let regular_count: usize = self.read_count(index, "class count")?;
        self.assign_nodes(index, regular_count, DartGraphNodeKind::Class, None)?;
        Ok(DartGraphAllocation::Class { predefined_count })
    }

    fn allocate_code(&mut self, index: usize) -> Result<DartGraphAllocation> {
        let primary_count: usize = self.read_count(index, "code count")?;
        for _ in 0..primary_count {
            let _state_bits: i32 = self.cursor.read_i32("code state bits")?;
            self.assign_nodes(index, 1, DartGraphNodeKind::Other, Some(18))?;
        }
        let deferred_count: usize = self.read_count(index, "deferred code count")?;
        for _ in 0..deferred_count {
            let _state_bits: i32 = self.cursor.read_i32("deferred code state bits")?;
            self.assign_nodes(index, 1, DartGraphNodeKind::Other, Some(18))?;
        }
        Ok(DartGraphAllocation::Code { primary_count })
    }

    fn allocate_instances(&mut self, index: usize, class_id: u32) -> Result<DartGraphAllocation> {
        let count: usize = self.read_count(index, "instance count")?;
        let next_raw: i32 = self.cursor.read_i32("next field words")?;
        let size_raw: i32 = self.cursor.read_i32("instance size words")?;
        let next_field_words: usize =
            positive_usize(index, "next field words", next_raw, self.cursor.position())?;
        let instance_size_words: usize = positive_usize(
            index,
            "instance size words",
            size_raw,
            self.cursor.position(),
        )?;
        if next_field_words < self.layout.instance_header_words
            || instance_size_words < next_field_words
            || instance_size_words > self.limits.variable_length
        {
            return Err(Error::DartGraphInvalidClusterValue {
                index,
                field: "instance size words",
                value: i64::from(size_raw),
                offset: self.cursor.position(),
            });
        }
        self.assign_nodes(
            index,
            count,
            DartGraphNodeKind::Other,
            Some(class_id as i32),
        )?;
        Ok(DartGraphAllocation::Instance {
            next_field_words,
            instance_size_words,
        })
    }

    fn allocate_mints(&mut self, index: usize) -> Result<DartGraphAllocation> {
        let count: usize = self.read_count(index, "integer count")?;
        for _ in 0..count {
            let value: i64 = self.cursor.read_i64("mint value")?;
            let reference: usize = self.next_reference;
            self.assign_nodes(index, 1, DartGraphNodeKind::Other, Some(MINT_CLASS_ID))?;
            self.node_mut(reference)?.immediate = Some(value);
        }
        Ok(DartGraphAllocation::Fixed)
    }

    fn allocate_lengths(
        &mut self,
        index: usize,
        kind: DartClusterBodyKind,
        class_id: u32,
    ) -> Result<DartGraphAllocation> {
        let count: usize = self.read_count(index, "object count")?;
        let mut lengths: Vec<usize> = Vec::with_capacity(count);
        for _ in 0..count {
            let encoded: usize = self.read_variable_length(index)?;
            let length: usize = if kind == DartClusterBodyKind::String {
                encoded >> 1
            } else {
                encoded
            };
            if kind == DartClusterBodyKind::String && length > self.limits.string_code_units {
                return Err(Error::DartGraphLimitExceeded {
                    resource: "string code units",
                    offset: self.cursor.position(),
                    actual: length,
                    limit: self.limits.string_code_units,
                });
            }
            lengths.push(encoded);
            self.assign_nodes(index, 1, node_kind(kind), Some(class_id as i32))?;
        }
        Ok(DartGraphAllocation::Lengths(lengths))
    }

    fn assign_nodes(
        &mut self,
        index: usize,
        count: usize,
        kind: DartGraphNodeKind,
        class_id: Option<i32>,
    ) -> Result<()> {
        let end: usize =
            self.next_reference
                .checked_add(count)
                .ok_or(Error::DartGraphAllocationMismatch {
                    index,
                    actual: usize::MAX,
                    expected: self.object_count,
                })?;
        if end.saturating_sub(1) > self.object_count {
            return Err(Error::DartGraphAllocationMismatch {
                index,
                actual: end.saturating_sub(1),
                expected: self.object_count,
            });
        }
        for reference in self.next_reference..end {
            let node: &mut DartGraphNode =
                self.nodes
                    .get_mut(reference)
                    .ok_or(Error::DartGraphAllocationMismatch {
                        index,
                        actual: reference,
                        expected: self.object_count,
                    })?;
            node.kind = kind;
            node.class_id = class_id;
        }
        self.next_reference = end;
        Ok(())
    }

    fn read_canonical_layout(&mut self, index: usize, count: usize) -> Result<()> {
        let table_length: usize = self.read_variable_length(index)?;
        let first_element: usize = self.read_variable_length(index)?;
        if table_length > self.limits.variable_length || first_element > count {
            return Err(Error::DartGraphInvalidClusterValue {
                index,
                field: "canonical set layout",
                value: i64::try_from(table_length).unwrap_or(i64::MAX),
                offset: self.cursor.position(),
            });
        }
        let gap_count: usize = count.saturating_sub(first_element);
        for _ in 0..gap_count {
            let gap: usize = self.read_variable_length(index)?;
            if gap > table_length {
                return Err(Error::DartGraphInvalidClusterValue {
                    index,
                    field: "canonical set gap",
                    value: i64::try_from(gap).unwrap_or(i64::MAX),
                    offset: self.cursor.position(),
                });
            }
        }
        Ok(())
    }

    fn uses_canonical_set(&self, kind: DartClusterBodyKind) -> bool {
        match kind {
            DartClusterBodyKind::String => self.role == DartGraphSnapshotRole::Isolate,
            DartClusterBodyKind::Type
            | DartClusterBodyKind::TypeArguments
            | DartClusterBodyKind::FunctionType
            | DartClusterBodyKind::RecordType
            | DartClusterBodyKind::TypeParameter => true,
            _ => false,
        }
    }

    fn read_fill(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        match cluster.kind {
            DartClusterBodyKind::Array => self.fill_arrays(cluster),
            DartClusterBodyKind::Class => self.fill_classes(cluster),
            DartClusterBodyKind::Closure => self.fill_fixed_references(cluster, 6),
            DartClusterBodyKind::ClosureData => self.fill_closure_data(cluster),
            DartClusterBodyKind::Code => self.fill_code(cluster),
            DartClusterBodyKind::CodeSourceMap | DartClusterBodyKind::PcDescriptors => {
                self.fill_byte_payloads(cluster, 1)
            }
            DartClusterBodyKind::Double => self.fill_compact_i64(cluster),
            DartClusterBodyKind::ExceptionHandlers => self.fill_exception_handlers(cluster),
            DartClusterBodyKind::Field => self.fill_fields(cluster),
            DartClusterBodyKind::Function => self.fill_functions(cluster),
            DartClusterBodyKind::FunctionType => self.fill_function_types(cluster),
            DartClusterBodyKind::GrowableObjectArray => self.fill_fixed_references(cluster, 3),
            DartClusterBodyKind::Instance => self.fill_instances(cluster),
            DartClusterBodyKind::Library => self.fill_libraries(cluster),
            DartClusterBodyKind::LoadingUnit => self.fill_loading_units(cluster),
            DartClusterBodyKind::Map | DartClusterBodyKind::Set => {
                self.fill_fixed_references(cluster, 5)
            }
            DartClusterBodyKind::Mint => Ok(()),
            DartClusterBodyKind::ObjectPool => self.fill_object_pools(cluster),
            DartClusterBodyKind::PatchClass => self.fill_fixed_references(
                cluster,
                self.layout.declarations.patch_class.reference_count,
            ),
            DartClusterBodyKind::Record => self.fill_records(cluster),
            DartClusterBodyKind::RecordType => self.fill_record_types(cluster),
            DartClusterBodyKind::Script => self.fill_scripts(cluster),
            DartClusterBodyKind::String => self.fill_strings(cluster),
            DartClusterBodyKind::SubtypeTestCache => self.fill_subtype_test_caches(cluster),
            DartClusterBodyKind::Type => self.fill_types(cluster),
            DartClusterBodyKind::TypeArguments => self.fill_type_arguments(cluster),
            DartClusterBodyKind::TypedData => self.fill_typed_data(cluster),
            DartClusterBodyKind::TypeParameter => self.fill_type_parameters(cluster),
            DartClusterBodyKind::TypeParameters => self.fill_fixed_references(cluster, 4),
            DartClusterBodyKind::UnlinkedCall => self.fill_unlinked_calls(cluster),
            DartClusterBodyKind::WeakArray => self.fill_weak_arrays(cluster),
        }
    }

    fn fill_classes(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let layout: super::dart_graph_layout::DartClassBodyLayout = self.layout.declarations.class;
        let predefined_count: usize = match cluster.allocation {
            DartGraphAllocation::Class { predefined_count } => predefined_count,
            _ => 0,
        };
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let references: Vec<u32> = self.read_references(layout.reference_count)?;
            let class_id: i32 = self.cursor.read_i32("class id")?;
            if class_id < 0 {
                return Err(Error::DartGraphInvalidClusterValue {
                    index: cluster.index,
                    field: "class id",
                    value: i64::from(class_id),
                    offset: self.cursor.position(),
                });
            }
            let _instance_size: i32 = self.cursor.read_i32("instance size")?;
            let _next_field_offset: i32 = self.cursor.read_i32("next field offset")?;
            let _type_arguments_offset: i32 = self.cursor.read_i32("type arguments offset")?;
            let _type_argument_count: i16 = self.cursor.read_i16("type argument count")?;
            let _native_field_count: u16 = self.cursor.read_u16("native field count")?;
            let _state_bits: u32 = self.cursor.read_u32("class state bits")?;
            if position < predefined_count || class_id < layout.top_level_class_id_offset {
                let _unboxed_fields: u64 = self.cursor.read_unsigned("unboxed fields")?;
            }
            let node: &mut DartGraphNode = self.node_mut(reference)?;
            node.references = references;
            node.class_id = Some(class_id);
        }
        Ok(())
    }

    fn fill_functions(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let reference_count: usize = self.layout.declarations.function.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(reference_count)?;
            let _code_index: u64 = self.cursor.read_unsigned("function code index")?;
            let _kind_tag: u32 = self.cursor.read_u32("function kind tag")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_fields(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let reference_count: usize = self.layout.declarations.field.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let mut references: Vec<u32> = self.read_references(reference_count)?;
            let _kind_bits: u32 = self.cursor.read_u32("field kind bits")?;
            let host_offset: u32 = self.cursor.read_ref(self.object_count)?;
            references.push(host_offset);
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_libraries(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let reference_count: usize = self.layout.declarations.library.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(reference_count)?;
            let _index: i32 = self.cursor.read_i32("library index")?;
            let _import_count: u16 = self.cursor.read_u16("library import count")?;
            let _load_state: u8 = self.cursor.read_u8("library load state")?;
            let _flags: u8 = self.cursor.read_u8("library flags")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_closure_data(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(2)?;
            let _packed_fields: u64 = self.cursor.read_unsigned("closure data packed fields")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_code(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let primary_count: usize = match cluster.allocation {
            DartGraphAllocation::Code { primary_count } => primary_count,
            _ => 0,
        };
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            if position < primary_count {
                let _payload_info: u64 = self.cursor.read_unsigned("code payload info")?;
            }
            let references: Vec<u32> = self.read_references(6)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_function_types(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(6)?;
            let _flags: u8 = self.cursor.read_u8("function type flags")?;
            let packed: u32 = self
                .cursor
                .read_u32("function type packed parameter counts")?;
            let _type_parameter_counts: u16 =
                self.cursor.read_u16("function type parameter counts")?;
            let implicit: usize = usize::try_from(packed & 1).unwrap_or(0);
            let fixed: usize = usize::try_from((packed >> 2) & 0x3fff).unwrap_or(0);
            let optional: usize = usize::try_from((packed >> 16) & 0x3fff).unwrap_or(0);
            let parameter_count: usize = fixed.saturating_add(optional).saturating_sub(implicit);
            let node: &mut DartGraphNode = self.node_mut(reference)?;
            node.references = references;
            node.parameter_count = Some(parameter_count);
        }
        Ok(())
    }

    fn fill_types(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(3)?;
            let _flags: u64 = self.cursor.read_unsigned("type flags")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_record_types(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(4)?;
            let _flags: u8 = self.cursor.read_u8("record type flags")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_type_parameters(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(3)?;
            let _base: u16 = self.cursor.read_u16("type parameter base")?;
            let _index: u16 = self.cursor.read_u16("type parameter index")?;
            let _flags: u8 = self.cursor.read_u8("type parameter flags")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_type_arguments(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "type argument length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let _hash: i32 = self.cursor.read_i32("type arguments hash")?;
            let _nullability: u64 = self.cursor.read_unsigned("type arguments nullability")?;
            let reference_count: usize =
                expected
                    .checked_add(1)
                    .ok_or_else(|| Error::DartGraphLimitExceeded {
                        resource: "references",
                        offset: self.cursor.position(),
                        actual: usize::MAX,
                        limit: self.limits.references,
                    })?;
            let references: Vec<u32> = self.read_references(reference_count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_arrays(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "array length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let reference_count: usize =
                expected
                    .checked_add(1)
                    .ok_or_else(|| Error::DartGraphLimitExceeded {
                        resource: "references",
                        offset: self.cursor.position(),
                        actual: usize::MAX,
                        limit: self.limits.references,
                    })?;
            let references: Vec<u32> = self.read_references(reference_count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_weak_arrays(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "weak array length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let references: Vec<u32> = self.read_references(expected)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_records(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "record field count",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let _shape: u64 = self.cursor.read_unsigned("record shape")?;
            let references: Vec<u32> = self.read_references(expected)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_strings(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected_encoded: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "string length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual_encoded: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual_encoded, expected_encoded)?;
            let length: usize = expected_encoded >> 1;
            let two_byte: bool = expected_encoded & 1 != 0;
            let byte_length: usize = if two_byte {
                length
                    .checked_mul(2)
                    .ok_or_else(|| Error::DartGraphLimitExceeded {
                        resource: "string bytes",
                        offset: self.cursor.position(),
                        actual: usize::MAX,
                        limit: self.limits.total_string_bytes,
                    })?
            } else {
                length
            };
            self.total_string_bytes = self
                .total_string_bytes
                .checked_add(byte_length)
                .ok_or_else(|| Error::DartGraphLimitExceeded {
                    resource: "string bytes",
                    offset: self.cursor.position(),
                    actual: usize::MAX,
                    limit: self.limits.total_string_bytes,
                })?;
            if self.total_string_bytes > self.limits.total_string_bytes {
                return Err(Error::DartGraphLimitExceeded {
                    resource: "string bytes",
                    offset: self.cursor.position(),
                    actual: self.total_string_bytes,
                    limit: self.limits.total_string_bytes,
                });
            }
            let bytes: &[u8] = self.cursor.read_bytes(byte_length, "string bytes")?;
            let (text, escaped): (Option<String>, bool) = if two_byte {
                match decode_two_byte_string(bytes) {
                    Some(decoded) => (Some(decoded), false),
                    None => (Some(escape_two_byte_string(bytes)), true),
                }
            } else {
                (Some(decode_one_byte_string(bytes)), false)
            };
            let node: &mut DartGraphNode = self.node_mut(reference)?;
            node.text = text;
            node.text_is_escaped = escaped;
        }
        Ok(())
    }

    fn fill_typed_data(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        let element_size: usize = self
            .layout
            .typed_data_element_size(cluster.class_id)
            .ok_or(Error::DartGraphUnsupportedCluster {
                index: cluster.index,
                cid: cluster.class_id,
                offset: cluster.allocation_offset,
            })?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "typed data length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let byte_length: usize = expected.checked_mul(element_size).ok_or_else(|| {
                Error::DartGraphLimitExceeded {
                    resource: "typed data bytes",
                    offset: self.cursor.position(),
                    actual: usize::MAX,
                    limit: self.limits.variable_length,
                }
            })?;
            if byte_length > self.limits.variable_length {
                return Err(Error::DartGraphLimitExceeded {
                    resource: "typed data bytes",
                    offset: self.cursor.position(),
                    actual: byte_length,
                    limit: self.limits.variable_length,
                });
            }
            let _bytes: &[u8] = self.cursor.read_bytes(byte_length, "typed data bytes")?;
        }
        Ok(())
    }

    fn fill_byte_payloads(&mut self, cluster: &DartGraphCluster, scale: usize) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "payload length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let byte_length: usize =
                expected
                    .checked_mul(scale)
                    .ok_or_else(|| Error::DartGraphLimitExceeded {
                        resource: "payload bytes",
                        offset: self.cursor.position(),
                        actual: usize::MAX,
                        limit: self.limits.variable_length,
                    })?;
            let _bytes: &[u8] = self.cursor.read_bytes(byte_length, "payload bytes")?;
        }
        Ok(())
    }

    fn fill_exception_handlers(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "exception handler count",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let packed: usize = self.read_variable_length(cluster.index)?;
            let actual: usize = packed >> 1;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let handled_types: u32 = self.cursor.read_ref(self.object_count)?;
            self.node_mut(reference)?.references = vec![handled_types];
            for _ in 0..expected {
                let _handler_offset: u32 = self.cursor.read_u32("exception handler offset")?;
                let _outer_try_index: i16 = self.cursor.read_i16("exception outer try index")?;
                let _needs_stacktrace: u8 = self.cursor.read_u8("exception needs stacktrace")?;
                let _has_catch_all: u8 = self.cursor.read_u8("exception has catch all")?;
                let _is_generated: u8 = self.cursor.read_u8("exception is generated")?;
            }
        }
        Ok(())
    }

    fn fill_object_pools(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize =
                *lengths
                    .get(position)
                    .ok_or_else(|| Error::DartGraphInvalidClusterValue {
                        index: cluster.index,
                        field: "object pool length",
                        value: -1,
                        offset: self.cursor.position(),
                    })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let mut references: Vec<u32> = Vec::new();
            let mut slots: Vec<DartPoolSlot> = Vec::with_capacity(expected.min(MAX_POOL_SLOTS));
            for _ in 0..expected {
                let bits: u8 = self.cursor.read_u8("object pool entry bits")?;
                let behavior: u8 = (bits >> 5) & 0x7;
                let entry_type: u8 = bits & 0x0f;
                let slot: DartPoolSlot = match behavior {
                    0 => match entry_type {
                        0 => {
                            let immediate: i64 = self.cursor.read_i64("object pool immediate")?;
                            DartPoolSlot::Immediate(immediate)
                        }
                        1 => {
                            let resolved: u32 = self.cursor.read_ref(self.object_count)?;
                            references.push(resolved);
                            DartPoolSlot::Object(resolved)
                        }
                        2 => DartPoolSlot::NativeFunction,
                        _ => {
                            return Err(Error::DartGraphInvalidObjectPoolEntry {
                                index: cluster.index,
                                object: u32::try_from(reference).unwrap_or(u32::MAX),
                                bits,
                            });
                        }
                    },
                    2..=4 => DartPoolSlot::Unmodelled,
                    _ => {
                        return Err(Error::DartGraphInvalidObjectPoolEntry {
                            index: cluster.index,
                            object: u32::try_from(reference).unwrap_or(u32::MAX),
                            bits,
                        });
                    }
                };
                if slots.len() < MAX_POOL_SLOTS {
                    slots.push(slot);
                }
            }
            let node: &mut DartGraphNode = self.node_mut(reference)?;
            node.references = references;
            node.pool_slots = slots;
        }
        Ok(())
    }

    fn fill_instances(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        let (next_field_words, instance_size_words): (usize, usize) = match cluster.allocation {
            DartGraphAllocation::Instance {
                next_field_words,
                instance_size_words,
            } => (next_field_words, instance_size_words),
            _ => {
                return Err(Error::DartGraphInvalidClusterValue {
                    index: cluster.index,
                    field: "instance allocation",
                    value: -1,
                    offset: self.cursor.position(),
                });
            }
        };
        if instance_size_words < next_field_words {
            return Err(Error::DartGraphInvalidClusterValue {
                index: cluster.index,
                field: "instance size words",
                value: i64::try_from(instance_size_words).unwrap_or(i64::MAX),
                offset: self.cursor.position(),
            });
        }
        let unboxed_fields: u64 = self.cursor.read_unsigned("instance unboxed fields")?;
        for reference in cluster.start_reference..cluster.end_reference {
            let mut references: Vec<u32> = Vec::new();
            for word in self.layout.instance_header_words..next_field_words {
                if word < 64 && unboxed_fields & (1_u64 << word) != 0 {
                    for _ in 0..self.layout.word_32_parts {
                        let _raw_part: u32 = self.cursor.read_u32("instance unboxed field part")?;
                    }
                } else {
                    let resolved: u32 = self.cursor.read_ref(self.object_count)?;
                    references.push(resolved);
                }
            }
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_loading_units(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let parent: u32 = self.cursor.read_ref(self.object_count)?;
            let _unit_id: i64 = self.cursor.read_i64("loading unit id")?;
            self.node_mut(reference)?.references = vec![parent];
        }
        Ok(())
    }

    fn fill_subtype_test_caches(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let cache: u32 = self.cursor.read_ref(self.object_count)?;
            let _inputs: u32 = self.cursor.read_u32("subtype test cache inputs")?;
            let _occupied: u32 = self.cursor.read_u32("subtype test cache occupied")?;
            self.node_mut(reference)?.references = vec![cache];
        }
        Ok(())
    }

    fn fill_unlinked_calls(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(2)?;
            let _patchable: u8 = self.cursor.read_u8("unlinked call patchable")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_scripts(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(1)?;
            let _kernel_script_index: i32 = self.cursor.read_i32("script kernel index")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_fixed_references(&mut self, cluster: &DartGraphCluster, count: usize) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_compact_i64(&mut self, cluster: &DartGraphCluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let value: i64 = self.cursor.read_i64("compact i64 value")?;
            self.node_mut(reference)?.immediate = Some(value);
        }
        Ok(())
    }

    fn validate_repeated_length(
        &self,
        cluster: &DartGraphCluster,
        reference: usize,
        actual: usize,
        expected: usize,
    ) -> Result<()> {
        if actual != expected {
            return Err(Error::DartGraphRepeatedLengthMismatch {
                index: cluster.index,
                object: u32::try_from(reference).unwrap_or(u32::MAX),
                actual,
                expected,
                offset: self.cursor.position(),
            });
        }
        Ok(())
    }

    fn read_references(&mut self, count: usize) -> Result<Vec<u32>> {
        let updated: usize = self.reference_count.checked_add(count).ok_or_else(|| {
            Error::DartGraphLimitExceeded {
                resource: "references",
                offset: self.cursor.position(),
                actual: usize::MAX,
                limit: self.limits.references,
            }
        })?;
        if updated > self.limits.references {
            return Err(Error::DartGraphLimitExceeded {
                resource: "references",
                offset: self.cursor.position(),
                actual: updated,
                limit: self.limits.references,
            });
        }
        let mut references: Vec<u32> = Vec::with_capacity(count);
        for _ in 0..count {
            references.push(self.cursor.read_ref(self.object_count)?);
        }
        self.reference_count = updated;
        Ok(references)
    }

    fn read_count(&mut self, index: usize, field: &'static str) -> Result<usize> {
        let value: usize = self.read_variable_length(index)?;
        if value > self.limits.objects {
            return Err(Error::DartGraphLimitExceeded {
                resource: field,
                offset: self.cursor.position(),
                actual: value,
                limit: self.limits.objects,
            });
        }
        Ok(value)
    }

    fn read_variable_length(&mut self, index: usize) -> Result<usize> {
        let raw: u64 = self.cursor.read_unsigned("variable length")?;
        let value: usize =
            usize::try_from(raw).map_err(|_| Error::DartGraphInvalidClusterValue {
                index,
                field: "variable length",
                value: i64::MAX,
                offset: self.cursor.position(),
            })?;
        if value > self.limits.variable_length {
            return Err(Error::DartGraphLimitExceeded {
                resource: "variable length",
                offset: self.cursor.position(),
                actual: value,
                limit: self.limits.variable_length,
            });
        }
        Ok(value)
    }

    fn node_mut(&mut self, reference: usize) -> Result<&mut DartGraphNode> {
        let offset: usize = self.cursor.position();
        self.nodes
            .get_mut(reference)
            .ok_or_else(|| Error::DartGraphReferenceOutOfBounds {
                reference: u32::try_from(reference).unwrap_or(u32::MAX),
                objects: self.object_count,
                offset,
            })
    }
}

fn allocation_lengths(cluster: &DartGraphCluster) -> Result<&[usize]> {
    match &cluster.allocation {
        DartGraphAllocation::Lengths(lengths) => Ok(lengths),
        _ => Err(Error::DartGraphInvalidClusterValue {
            index: cluster.index,
            field: "allocation lengths",
            value: -1,
            offset: cluster.allocation_end,
        }),
    }
}

const fn node_kind(kind: DartClusterBodyKind) -> DartGraphNodeKind {
    match kind {
        DartClusterBodyKind::Class => DartGraphNodeKind::Class,
        DartClusterBodyKind::PatchClass => DartGraphNodeKind::PatchClass,
        DartClusterBodyKind::Function => DartGraphNodeKind::Function,
        DartClusterBodyKind::Field => DartGraphNodeKind::Field,
        DartClusterBodyKind::Library => DartGraphNodeKind::Library,
        DartClusterBodyKind::String => DartGraphNodeKind::String,
        DartClusterBodyKind::FunctionType => DartGraphNodeKind::FunctionType,
        _ => DartGraphNodeKind::Other,
    }
}

fn to_usize(value: u64, resource: &'static str, limit: usize, offset: usize) -> Result<usize> {
    let converted: usize = usize::try_from(value).map_err(|_| Error::DartGraphLimitExceeded {
        resource,
        offset,
        actual: usize::MAX,
        limit,
    })?;
    if converted > limit {
        return Err(Error::DartGraphLimitExceeded {
            resource,
            offset,
            actual: converted,
            limit,
        });
    }
    Ok(converted)
}

fn positive_usize(index: usize, field: &'static str, value: i32, offset: usize) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::DartGraphInvalidClusterValue {
        index,
        field,
        value: i64::from(value),
        offset,
    })
}

fn decode_one_byte_string(bytes: &[u8]) -> String {
    let mut text: String = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(*byte));
    }
    text
}

fn escape_two_byte_string(bytes: &[u8]) -> String {
    let unit_count: usize = bytes.len() / 2;
    let mut text: String = String::with_capacity(unit_count.saturating_mul(3));
    for character in char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        match character {
            Ok(decoded) => text.push(decoded),
            Err(error) => {
                let unit: u16 = error.unpaired_surrogate();
                let _ = write!(text, "\\u{unit:04X}");
            }
        }
    }
    text
}

fn decode_two_byte_string(bytes: &[u8]) -> Option<String> {
    let unit_count: usize = bytes.len() / 2;
    let mut text: String = String::with_capacity(unit_count.saturating_mul(3));
    for character in char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        let Ok(character): std::result::Result<char, std::char::DecodeUtf16Error> = character
        else {
            return None;
        };
        text.push(character);
    }
    Some(text)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{decode_one_byte_string, decode_two_byte_string};

    #[test]
    fn decodes_one_byte_latin1() {
        let decoded: String = decode_one_byte_string(&[65, 233]);
        assert_eq!(decoded, "A\u{e9}");
    }

    #[test]
    fn decodes_two_byte_utf16() {
        let decoded: Option<String> = decode_two_byte_string(&[65, 0, 61, 216, 0, 222]);
        assert_eq!(decoded.as_deref(), Some("A\u{1f600}"));
    }

    #[test]
    fn rejects_unpaired_two_byte_surrogate() {
        let decoded: Option<String> = decode_two_byte_string(&[61, 216]);
        assert!(decoded.is_none());
    }
}
