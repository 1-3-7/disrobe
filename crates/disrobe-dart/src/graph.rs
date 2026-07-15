use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::header::SnapshotHeader;
use crate::layout::{ClusterLayout, LayoutDescriptor};
use crate::limits::RecoveryLimits;
use crate::stream::SnapshotStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnapshotRole {
    Vm,
    Isolate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NodeKind {
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

#[derive(Debug)]
pub(super) struct Node {
    pub(super) kind: NodeKind,
    pub(super) references: Vec<u32>,
    pub(super) text: Option<String>,
    pub(super) class_id: Option<i32>,
    pub(super) parameter_count: Option<usize>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            kind: NodeKind::Unknown,
            references: Vec::new(),
            text: None,
            class_id: None,
            parameter_count: None,
        }
    }
}

impl Node {
    fn try_clone(&self) -> Result<Self> {
        let mut references: Vec<u32> = Vec::new();
        reserve_exact(
            &mut references,
            "base node references",
            self.references.len(),
        )?;
        references.extend_from_slice(&self.references);
        let text: Option<String> = match self.text.as_deref() {
            Some(value) => {
                let mut cloned: String = String::new();
                cloned.try_reserve_exact(value.len()).map_err(
                    |_error: std::collections::TryReserveError| Error::AllocationFailed {
                        resource: "base node text",
                        requested: value.len(),
                    },
                )?;
                cloned.push_str(value);
                Some(cloned)
            }
            None => None,
        };
        Ok(Self {
            kind: self.kind,
            references,
            text,
            class_id: self.class_id,
            parameter_count: self.parameter_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub index: usize,
    pub class_id: u32,
    pub layout: ClusterLayout,
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
pub struct SnapshotSummary {
    pub base_objects: usize,
    pub total_objects: usize,
    pub cluster_count: usize,
    pub instruction_count: usize,
    pub instruction_table_data_offset: usize,
    pub clustered_offset: usize,
    pub parsed_offset: usize,
    pub clusters: Vec<ClusterSummary>,
}

#[derive(Debug)]
pub(super) struct ParsedSnapshot {
    pub(super) nodes: Vec<Node>,
    pub(super) summary: SnapshotSummary,
}

#[derive(Debug)]
enum AllocationData {
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
struct Cluster {
    index: usize,
    class_id: u32,
    layout: ClusterLayout,
    canonical: bool,
    deeply_immutable: bool,
    start_reference: usize,
    end_reference: usize,
    allocation_offset: usize,
    allocation_end: usize,
    fill_offset: usize,
    fill_end: usize,
    allocation: AllocationData,
}

struct GraphParser<'data> {
    stream: SnapshotStream<'data>,
    descriptor: LayoutDescriptor,
    limits: RecoveryLimits,
    role: SnapshotRole,
    object_count: usize,
    nodes: Vec<Node>,
    next_reference: usize,
    reference_count: usize,
    total_string_bytes: usize,
}

pub(super) fn parse_graph(
    bytes: &[u8],
    header: &SnapshotHeader,
    role: SnapshotRole,
    base_nodes: Option<&[Node]>,
    descriptor: LayoutDescriptor,
    limits: RecoveryLimits,
) -> Result<ParsedSnapshot> {
    let declared: &[u8] =
        bytes
            .get(..header.declared_length)
            .ok_or(Error::DeclaredLengthOutOfBounds {
                declared: header.declared_length,
                available: bytes.len(),
            })?;
    let mut stream: SnapshotStream<'_> = SnapshotStream::new(declared, header.clustered_offset)?;
    let base_objects: usize = to_usize(stream.read_unsigned()?, "base objects", limits.objects)?;
    let total_objects: usize = to_usize(stream.read_unsigned()?, "objects", limits.objects)?;
    let cluster_count: usize = to_usize(stream.read_unsigned()?, "clusters", limits.clusters)?;
    let instruction_count: usize = to_usize(
        stream.read_unsigned()?,
        "instructions",
        limits.variable_length,
    )?;
    let instruction_table_data_offset: usize = to_usize(
        stream.read_unsigned()?,
        "instruction table offset",
        limits.variable_length,
    )?;
    if base_objects > total_objects {
        return Err(Error::InvalidObjectCounts {
            base: base_objects,
            total: total_objects,
        });
    }
    let node_count: usize = total_objects
        .checked_add(1)
        .ok_or(Error::AllocationFailed {
            resource: "object nodes",
            requested: usize::MAX,
        })?;
    let mut nodes: Vec<Node> = Vec::new();
    reserve_exact(&mut nodes, "object nodes", node_count)?;
    nodes.resize_with(node_count, Node::default);
    if let Some(base) = base_nodes {
        let expected: usize = base.len().saturating_sub(1);
        if base_objects != expected {
            return Err(Error::BaseObjectMismatch {
                actual: base_objects,
                expected,
            });
        }
        let destination: &mut [Node] =
            nodes
                .get_mut(..=base_objects)
                .ok_or(Error::InvalidObjectCounts {
                    base: base_objects,
                    total: total_objects,
                })?;
        for (output, source) in destination.iter_mut().zip(base) {
            *output = source.try_clone()?;
        }
    }
    let mut parser: GraphParser<'_> = GraphParser {
        stream,
        descriptor,
        limits,
        role,
        object_count: total_objects,
        nodes,
        next_reference: base_objects.saturating_add(1),
        reference_count: 0,
        total_string_bytes: 0,
    };
    let mut clusters: Vec<Cluster> = Vec::new();
    reserve_exact(&mut clusters, "clusters", cluster_count)?;
    for index in 0..cluster_count {
        let cluster: Cluster = parser.read_allocation(index)?;
        clusters.push(cluster);
    }
    let allocated: usize = parser.next_reference.saturating_sub(1);
    if allocated != total_objects {
        return Err(Error::ObjectAllocationMismatch {
            index: cluster_count,
            actual: allocated,
            expected: total_objects,
        });
    }
    for (index, output_cluster) in clusters.iter_mut().enumerate() {
        let fill_offset: usize = parser.stream.position();
        if let Err(source) = parser.read_fill(output_cluster) {
            return Err(Error::ClusterFill {
                index,
                offset: parser.stream.position(),
                source: Box::new(source),
            });
        }
        output_cluster.fill_offset = fill_offset;
        output_cluster.fill_end = parser.stream.position();
    }
    let parsed_offset: usize = parser.stream.position();
    let cluster_summaries: Vec<ClusterSummary> = clusters
        .into_iter()
        .map(|cluster: Cluster| ClusterSummary {
            index: cluster.index,
            class_id: cluster.class_id,
            layout: cluster.layout,
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
    Ok(ParsedSnapshot {
        nodes: parser.nodes,
        summary: SnapshotSummary {
            base_objects,
            total_objects,
            cluster_count,
            instruction_count,
            instruction_table_data_offset,
            clustered_offset: header.clustered_offset,
            parsed_offset,
            clusters: cluster_summaries,
        },
    })
}

impl GraphParser<'_> {
    fn read_allocation(&mut self, index: usize) -> Result<Cluster> {
        let allocation_offset: usize = self.stream.position();
        let tags: u32 = self.stream.read_u32()?;
        let class_id: u32 = (tags >> 12) & 0x000f_ffff;
        let canonical: bool = tags & 0x2 != 0;
        let deeply_immutable: bool = tags & 0x80 != 0;
        let layout: ClusterLayout =
            self.descriptor
                .cluster_layout(class_id)
                .ok_or(Error::UnsupportedCluster {
                    index,
                    cid: class_id,
                    offset: allocation_offset,
                })?;
        let start_reference: usize = self.next_reference;
        let allocation: AllocationData = match layout {
            ClusterLayout::Class => self.allocate_classes(index)?,
            ClusterLayout::Code => self.allocate_code(index)?,
            ClusterLayout::Instance => self.allocate_instances(index, class_id)?,
            ClusterLayout::Mint => self.allocate_mints(index)?,
            ClusterLayout::Array
            | ClusterLayout::ObjectPool
            | ClusterLayout::PcDescriptors
            | ClusterLayout::CodeSourceMap
            | ClusterLayout::ExceptionHandlers
            | ClusterLayout::Record
            | ClusterLayout::String
            | ClusterLayout::TypeArguments
            | ClusterLayout::TypedData
            | ClusterLayout::WeakArray => self.allocate_lengths(index, layout, class_id)?,
            _ => self.allocate_fixed(index, layout, class_id)?,
        };
        let end_reference: usize = self.next_reference;
        let count: usize = end_reference.saturating_sub(start_reference);
        if canonical && self.uses_canonical_set(layout) {
            self.read_canonical_layout(index, count)?;
        }
        Ok(Cluster {
            index,
            class_id,
            layout,
            canonical,
            deeply_immutable,
            start_reference,
            end_reference,
            allocation_offset,
            allocation_end: self.stream.position(),
            fill_offset: 0,
            fill_end: 0,
            allocation,
        })
    }

    fn allocate_fixed(
        &mut self,
        index: usize,
        layout: ClusterLayout,
        class_id: u32,
    ) -> Result<AllocationData> {
        let count: usize = self.read_count(index, "object count")?;
        self.assign_nodes(index, count, node_kind(layout), Some(class_id as i32))?;
        Ok(AllocationData::Fixed)
    }

    fn allocate_classes(&mut self, index: usize) -> Result<AllocationData> {
        let predefined_count: usize = self.read_count(index, "predefined class count")?;
        for _ in 0..predefined_count {
            let class_id: i32 = self.stream.read_i32()?;
            if class_id < 0 {
                return Err(Error::InvalidClusterValue {
                    index,
                    field: "class id",
                    value: i64::from(class_id),
                });
            }
            self.assign_nodes(index, 1, NodeKind::Class, Some(class_id))?;
        }
        let regular_count: usize = self.read_count(index, "class count")?;
        self.assign_nodes(index, regular_count, NodeKind::Class, None)?;
        Ok(AllocationData::Class { predefined_count })
    }

    fn allocate_code(&mut self, index: usize) -> Result<AllocationData> {
        let primary_count: usize = self.read_count(index, "code count")?;
        for _ in 0..primary_count {
            let _state_bits: i32 = self.stream.read_i32()?;
            self.assign_nodes(index, 1, NodeKind::Other, Some(18))?;
        }
        let deferred_count: usize = self.read_count(index, "deferred code count")?;
        for _ in 0..deferred_count {
            let _state_bits: i32 = self.stream.read_i32()?;
            self.assign_nodes(index, 1, NodeKind::Other, Some(18))?;
        }
        Ok(AllocationData::Code { primary_count })
    }

    fn allocate_instances(&mut self, index: usize, class_id: u32) -> Result<AllocationData> {
        let count: usize = self.read_count(index, "instance count")?;
        let next_raw: i32 = self.stream.read_i32()?;
        let size_raw: i32 = self.stream.read_i32()?;
        let next_field_words: usize = positive_usize(index, "next field words", next_raw)?;
        let instance_size_words: usize = positive_usize(index, "instance size words", size_raw)?;
        if next_field_words < self.descriptor.instance_header_words
            || instance_size_words < next_field_words
            || instance_size_words > self.limits.variable_length
        {
            return Err(Error::InvalidClusterValue {
                index,
                field: "instance size words",
                value: i64::from(size_raw),
            });
        }
        self.assign_nodes(index, count, NodeKind::Other, Some(class_id as i32))?;
        Ok(AllocationData::Instance {
            next_field_words,
            instance_size_words,
        })
    }

    fn allocate_mints(&mut self, index: usize) -> Result<AllocationData> {
        let count: usize = self.read_count(index, "integer count")?;
        for _ in 0..count {
            let _value: i64 = self.stream.read_i64()?;
            self.assign_nodes(index, 1, NodeKind::Other, Some(61))?;
        }
        Ok(AllocationData::Fixed)
    }

    fn allocate_lengths(
        &mut self,
        index: usize,
        layout: ClusterLayout,
        class_id: u32,
    ) -> Result<AllocationData> {
        let count: usize = self.read_count(index, "object count")?;
        let mut lengths: Vec<usize> = Vec::new();
        reserve_exact(&mut lengths, "object lengths", count)?;
        for _ in 0..count {
            let encoded: usize = self.read_variable_length(index)?;
            let length: usize = if layout == ClusterLayout::String {
                encoded >> 1
            } else {
                encoded
            };
            if layout == ClusterLayout::String && length > self.limits.string_code_units {
                return Err(Error::LimitExceeded {
                    resource: "string code units",
                    actual: length,
                    limit: self.limits.string_code_units,
                });
            }
            lengths.push(encoded);
            self.assign_nodes(index, 1, node_kind(layout), Some(class_id as i32))?;
        }
        Ok(AllocationData::Lengths(lengths))
    }

    fn assign_nodes(
        &mut self,
        index: usize,
        count: usize,
        kind: NodeKind,
        class_id: Option<i32>,
    ) -> Result<()> {
        let end: usize =
            self.next_reference
                .checked_add(count)
                .ok_or(Error::ObjectAllocationMismatch {
                    index,
                    actual: usize::MAX,
                    expected: self.object_count,
                })?;
        if end.saturating_sub(1) > self.object_count {
            return Err(Error::ObjectAllocationMismatch {
                index,
                actual: end.saturating_sub(1),
                expected: self.object_count,
            });
        }
        for reference in self.next_reference..end {
            let node: &mut Node =
                self.nodes
                    .get_mut(reference)
                    .ok_or(Error::ObjectAllocationMismatch {
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
            return Err(Error::InvalidClusterValue {
                index,
                field: "canonical set layout",
                value: i64::try_from(table_length).unwrap_or(i64::MAX),
            });
        }
        let gap_count: usize = count.saturating_sub(first_element);
        for _ in 0..gap_count {
            let gap: usize = self.read_variable_length(index)?;
            if gap > table_length {
                return Err(Error::InvalidClusterValue {
                    index,
                    field: "canonical set gap",
                    value: i64::try_from(gap).unwrap_or(i64::MAX),
                });
            }
        }
        Ok(())
    }

    fn uses_canonical_set(&self, layout: ClusterLayout) -> bool {
        match layout {
            ClusterLayout::String => self.role == SnapshotRole::Isolate,
            ClusterLayout::Type
            | ClusterLayout::TypeArguments
            | ClusterLayout::FunctionType
            | ClusterLayout::RecordType
            | ClusterLayout::TypeParameter => true,
            _ => false,
        }
    }

    fn read_fill(&mut self, cluster: &Cluster) -> Result<()> {
        match cluster.layout {
            ClusterLayout::Array => self.fill_arrays(cluster),
            ClusterLayout::Class => self.fill_classes(cluster),
            ClusterLayout::Closure => self.fill_fixed_references(cluster, 6),
            ClusterLayout::ClosureData => self.fill_closure_data(cluster),
            ClusterLayout::Code => self.fill_code(cluster),
            ClusterLayout::CodeSourceMap | ClusterLayout::PcDescriptors => {
                self.fill_byte_payloads(cluster, 1)
            }
            ClusterLayout::Double => self.fill_compact_i64(cluster),
            ClusterLayout::ExceptionHandlers => self.fill_exception_handlers(cluster),
            ClusterLayout::Field => self.fill_fields(cluster),
            ClusterLayout::Function => self.fill_functions(cluster),
            ClusterLayout::FunctionType => self.fill_function_types(cluster),
            ClusterLayout::GrowableObjectArray => self.fill_fixed_references(cluster, 3),
            ClusterLayout::Instance => self.fill_instances(cluster),
            ClusterLayout::Library => self.fill_libraries(cluster),
            ClusterLayout::LoadingUnit => self.fill_loading_units(cluster),
            ClusterLayout::Map | ClusterLayout::Set => self.fill_fixed_references(cluster, 5),
            ClusterLayout::Mint => Ok(()),
            ClusterLayout::ObjectPool => self.fill_object_pools(cluster),
            ClusterLayout::PatchClass => self.fill_fixed_references(
                cluster,
                self.descriptor.declarations.patch_class.reference_count,
            ),
            ClusterLayout::Record => self.fill_records(cluster),
            ClusterLayout::RecordType => self.fill_record_types(cluster),
            ClusterLayout::Script => self.fill_scripts(cluster),
            ClusterLayout::String => self.fill_strings(cluster),
            ClusterLayout::SubtypeTestCache => self.fill_subtype_test_caches(cluster),
            ClusterLayout::Type => self.fill_types(cluster),
            ClusterLayout::TypeArguments => self.fill_type_arguments(cluster),
            ClusterLayout::TypedData => self.fill_typed_data(cluster),
            ClusterLayout::TypeParameter => self.fill_type_parameters(cluster),
            ClusterLayout::TypeParameters => self.fill_fixed_references(cluster, 4),
            ClusterLayout::UnlinkedCall => self.fill_unlinked_calls(cluster),
            ClusterLayout::WeakArray => self.fill_weak_arrays(cluster),
        }
    }

    fn fill_classes(&mut self, cluster: &Cluster) -> Result<()> {
        let layout: crate::layout::ClassDeclarationLayout = self.descriptor.declarations.class;
        let predefined_count: usize = match cluster.allocation {
            AllocationData::Class { predefined_count } => predefined_count,
            _ => 0,
        };
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let references: Vec<u32> = self.read_references(layout.reference_count)?;
            let class_id: i32 = self.stream.read_i32()?;
            if class_id < 0 {
                return Err(Error::InvalidClusterValue {
                    index: cluster.index,
                    field: "class id",
                    value: i64::from(class_id),
                });
            }
            let _instance_size: i32 = self.stream.read_i32()?;
            let _next_field_offset: i32 = self.stream.read_i32()?;
            let _type_arguments_offset: i32 = self.stream.read_i32()?;
            let _type_argument_count: i16 = self.stream.read_i16()?;
            let _native_field_count: u16 = self.stream.read_u16()?;
            let _state_bits: u32 = self.stream.read_u32()?;
            if position < predefined_count || class_id < layout.top_level_class_id_offset {
                let _unboxed_fields: u64 = self.stream.read_unsigned()?;
            }
            let node: &mut Node = self.node_mut(reference)?;
            node.references = references;
            node.class_id = Some(class_id);
        }
        Ok(())
    }

    fn fill_functions(&mut self, cluster: &Cluster) -> Result<()> {
        let reference_count: usize = self.descriptor.declarations.function.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(reference_count)?;
            let _code_index: u64 = self.stream.read_unsigned()?;
            let _kind_tag: u32 = self.stream.read_u32()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_fields(&mut self, cluster: &Cluster) -> Result<()> {
        let reference_count: usize = self.descriptor.declarations.field.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let mut references: Vec<u32> = self.read_references(reference_count)?;
            let _kind_bits: u32 = self.stream.read_u32()?;
            let host_offset: u32 = self.read_reference()?;
            push_fallible(&mut references, host_offset, "field references")?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_libraries(&mut self, cluster: &Cluster) -> Result<()> {
        let reference_count: usize = self.descriptor.declarations.library.reference_count;
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(reference_count)?;
            let _index: i32 = self.stream.read_i32()?;
            let _import_count: u16 = self.stream.read_u16()?;
            let _load_state: u8 = self.stream.read_u8()?;
            let _flags: u8 = self.stream.read_u8()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_closure_data(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(2)?;
            let _packed_fields: u64 = self.stream.read_unsigned()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_code(&mut self, cluster: &Cluster) -> Result<()> {
        let primary_count: usize = match cluster.allocation {
            AllocationData::Code { primary_count } => primary_count,
            _ => 0,
        };
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            if position < primary_count {
                let _payload_info: u64 = self.stream.read_unsigned()?;
            }
            let references: Vec<u32> = self.read_references(6)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_function_types(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(6)?;
            let _flags: u8 = self.stream.read_u8()?;
            let packed: u32 = self.stream.read_u32()?;
            let _type_parameter_counts: u16 = self.stream.read_u16()?;
            let implicit: usize = usize::try_from(packed & 1).unwrap_or(0);
            let fixed: usize = usize::try_from((packed >> 2) & 0x3fff).unwrap_or(0);
            let optional: usize = usize::try_from((packed >> 16) & 0x3fff).unwrap_or(0);
            let parameter_count: usize = fixed.saturating_add(optional).saturating_sub(implicit);
            let node: &mut Node = self.node_mut(reference)?;
            node.references = references;
            node.parameter_count = Some(parameter_count);
        }
        Ok(())
    }

    fn fill_types(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(3)?;
            let _flags: u64 = self.stream.read_unsigned()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_record_types(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(4)?;
            let _flags: u8 = self.stream.read_u8()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_type_parameters(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(3)?;
            let _base: u16 = self.stream.read_u16()?;
            let _index: u16 = self.stream.read_u16()?;
            let _flags: u8 = self.stream.read_u8()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_type_arguments(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "type argument length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let _hash: i32 = self.stream.read_i32()?;
            let _nullability: u64 = self.stream.read_unsigned()?;
            let reference_count: usize = expected.checked_add(1).ok_or(Error::LimitExceeded {
                resource: "references",
                actual: usize::MAX,
                limit: self.limits.references,
            })?;
            let references: Vec<u32> = self.read_references(reference_count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_arrays(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "array length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let reference_count: usize = expected.checked_add(1).ok_or(Error::LimitExceeded {
                resource: "references",
                actual: usize::MAX,
                limit: self.limits.references,
            })?;
            let references: Vec<u32> = self.read_references(reference_count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_weak_arrays(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "weak array length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let references: Vec<u32> = self.read_references(expected)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_records(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "record field count",
                value: -1,
            })?;
            let _shape: u64 = self.stream.read_unsigned()?;
            let references: Vec<u32> = self.read_references(expected)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_strings(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected_encoded: usize =
                *lengths.get(position).ok_or(Error::InvalidClusterValue {
                    index: cluster.index,
                    field: "string length",
                    value: -1,
                })?;
            let actual_encoded: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual_encoded, expected_encoded)?;
            let length: usize = expected_encoded >> 1;
            let two_byte: bool = expected_encoded & 1 != 0;
            let byte_length: usize = if two_byte {
                length.checked_mul(2).ok_or(Error::LimitExceeded {
                    resource: "string bytes",
                    actual: usize::MAX,
                    limit: self.limits.total_string_bytes,
                })?
            } else {
                length
            };
            self.total_string_bytes =
                self.total_string_bytes
                    .checked_add(byte_length)
                    .ok_or(Error::LimitExceeded {
                        resource: "string bytes",
                        actual: usize::MAX,
                        limit: self.limits.total_string_bytes,
                    })?;
            if self.total_string_bytes > self.limits.total_string_bytes {
                return Err(Error::LimitExceeded {
                    resource: "string bytes",
                    actual: self.total_string_bytes,
                    limit: self.limits.total_string_bytes,
                });
            }
            let bytes: &[u8] = self.stream.read_bytes(byte_length)?;
            let text: Option<String> = if two_byte {
                decode_two_byte_string(bytes)?
            } else {
                Some(decode_one_byte_string(bytes)?)
            };
            self.node_mut(reference)?.text = text;
        }
        Ok(())
    }

    fn fill_typed_data(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        let element_size: usize = self
            .descriptor
            .typed_data_element_size(cluster.class_id)
            .ok_or(Error::UnsupportedCluster {
                index: cluster.index,
                cid: cluster.class_id,
                offset: cluster.allocation_offset,
            })?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "typed data length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let byte_length: usize =
                expected
                    .checked_mul(element_size)
                    .ok_or(Error::LimitExceeded {
                        resource: "typed data bytes",
                        actual: usize::MAX,
                        limit: self.limits.variable_length,
                    })?;
            if byte_length > self.limits.variable_length {
                return Err(Error::LimitExceeded {
                    resource: "typed data bytes",
                    actual: byte_length,
                    limit: self.limits.variable_length,
                });
            }
            let _bytes: &[u8] = self.stream.read_bytes(byte_length)?;
        }
        Ok(())
    }

    fn fill_byte_payloads(&mut self, cluster: &Cluster, scale: usize) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "payload length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let byte_length: usize = expected.checked_mul(scale).ok_or(Error::LimitExceeded {
                resource: "payload bytes",
                actual: usize::MAX,
                limit: self.limits.variable_length,
            })?;
            let _bytes: &[u8] = self.stream.read_bytes(byte_length)?;
        }
        Ok(())
    }

    fn fill_exception_handlers(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "exception handler count",
                value: -1,
            })?;
            let packed: usize = self.read_variable_length(cluster.index)?;
            let actual: usize = packed >> 1;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let handled_types: u32 = self.read_reference()?;
            self.node_mut(reference)?.references = vec![handled_types];
            for _ in 0..expected {
                let _handler_offset: u32 = self.stream.read_u32()?;
                let _outer_try_index: i16 = self.stream.read_i16()?;
                let _needs_stacktrace: u8 = self.stream.read_u8()?;
                let _has_catch_all: u8 = self.stream.read_u8()?;
                let _is_generated: u8 = self.stream.read_u8()?;
            }
        }
        Ok(())
    }

    fn fill_object_pools(&mut self, cluster: &Cluster) -> Result<()> {
        let lengths: &[usize] = allocation_lengths(cluster)?;
        for (position, reference) in (cluster.start_reference..cluster.end_reference).enumerate() {
            let expected: usize = *lengths.get(position).ok_or(Error::InvalidClusterValue {
                index: cluster.index,
                field: "object pool length",
                value: -1,
            })?;
            let actual: usize = self.read_variable_length(cluster.index)?;
            self.validate_repeated_length(cluster, reference, actual, expected)?;
            let mut references: Vec<u32> = Vec::new();
            for _ in 0..expected {
                let bits: u8 = self.stream.read_u8()?;
                let behavior: u8 = (bits >> 5) & 0x7;
                let entry_type: u8 = bits & 0x0f;
                match behavior {
                    0 => match entry_type {
                        0 => {
                            let _immediate: i64 = self.stream.read_i64()?;
                        }
                        1 => {
                            let resolved: u32 = self.read_reference()?;
                            push_fallible(&mut references, resolved, "object pool references")?;
                        }
                        2 => {}
                        _ => {
                            return Err(Error::InvalidObjectPoolEntry {
                                index: cluster.index,
                                object: u32::try_from(reference).unwrap_or(u32::MAX),
                                bits,
                            });
                        }
                    },
                    2..=4 => {}
                    _ => {
                        return Err(Error::InvalidObjectPoolEntry {
                            index: cluster.index,
                            object: u32::try_from(reference).unwrap_or(u32::MAX),
                            bits,
                        });
                    }
                }
            }
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_instances(&mut self, cluster: &Cluster) -> Result<()> {
        let (next_field_words, instance_size_words): (usize, usize) = match cluster.allocation {
            AllocationData::Instance {
                next_field_words,
                instance_size_words,
            } => (next_field_words, instance_size_words),
            _ => {
                return Err(Error::InvalidClusterValue {
                    index: cluster.index,
                    field: "instance allocation",
                    value: -1,
                });
            }
        };
        if instance_size_words < next_field_words {
            return Err(Error::InvalidClusterValue {
                index: cluster.index,
                field: "instance size words",
                value: i64::try_from(instance_size_words).unwrap_or(i64::MAX),
            });
        }
        let unboxed_fields: u64 = self.stream.read_unsigned()?;
        for reference in cluster.start_reference..cluster.end_reference {
            let mut references: Vec<u32> = Vec::new();
            for word in self.descriptor.instance_header_words..next_field_words {
                if word < 64 && unboxed_fields & (1_u64 << word) != 0 {
                    for _ in 0..self.descriptor.word_32_parts {
                        let _raw_part: u32 = self.stream.read_u32()?;
                    }
                } else {
                    let resolved: u32 = self.read_reference()?;
                    push_fallible(&mut references, resolved, "instance references")?;
                }
            }
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_loading_units(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let parent: u32 = self.read_reference()?;
            let _unit_id: i64 = self.stream.read_i64()?;
            self.node_mut(reference)?.references = vec![parent];
        }
        Ok(())
    }

    fn fill_subtype_test_caches(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let cache: u32 = self.read_reference()?;
            let _inputs: u32 = self.stream.read_u32()?;
            let _occupied: u32 = self.stream.read_u32()?;
            self.node_mut(reference)?.references = vec![cache];
        }
        Ok(())
    }

    fn fill_unlinked_calls(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(2)?;
            let _patchable: u8 = self.stream.read_u8()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_scripts(&mut self, cluster: &Cluster) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(1)?;
            let _kernel_script_index: i32 = self.stream.read_i32()?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_fixed_references(&mut self, cluster: &Cluster, count: usize) -> Result<()> {
        for reference in cluster.start_reference..cluster.end_reference {
            let references: Vec<u32> = self.read_references(count)?;
            self.node_mut(reference)?.references = references;
        }
        Ok(())
    }

    fn fill_compact_i64(&mut self, cluster: &Cluster) -> Result<()> {
        for _ in cluster.start_reference..cluster.end_reference {
            let _value: i64 = self.stream.read_i64()?;
        }
        Ok(())
    }

    fn validate_repeated_length(
        &self,
        cluster: &Cluster,
        reference: usize,
        actual: usize,
        expected: usize,
    ) -> Result<()> {
        if actual != expected {
            return Err(Error::RepeatedLengthMismatch {
                index: cluster.index,
                object: u32::try_from(reference).unwrap_or(u32::MAX),
                actual,
                expected,
                offset: self.stream.position(),
            });
        }
        Ok(())
    }

    fn read_references(&mut self, count: usize) -> Result<Vec<u32>> {
        let updated: usize =
            self.reference_count
                .checked_add(count)
                .ok_or(Error::LimitExceeded {
                    resource: "references",
                    actual: usize::MAX,
                    limit: self.limits.references,
                })?;
        if updated > self.limits.references {
            return Err(Error::LimitExceeded {
                resource: "references",
                actual: updated,
                limit: self.limits.references,
            });
        }
        let mut references: Vec<u32> = Vec::new();
        reserve_exact(&mut references, "references", count)?;
        for _ in 0..count {
            references.push(self.read_reference()?);
        }
        self.reference_count = updated;
        Ok(references)
    }

    fn read_reference(&mut self) -> Result<u32> {
        let updated: usize = self
            .reference_count
            .checked_add(1)
            .ok_or(Error::LimitExceeded {
                resource: "references",
                actual: usize::MAX,
                limit: self.limits.references,
            })?;
        if updated > self.limits.references {
            return Err(Error::LimitExceeded {
                resource: "references",
                actual: updated,
                limit: self.limits.references,
            });
        }
        let reference: u32 = self.stream.read_ref(self.object_count)?;
        self.reference_count = updated;
        Ok(reference)
    }

    fn read_count(&mut self, index: usize, field: &'static str) -> Result<usize> {
        let value: usize = self.read_variable_length(index)?;
        if value > self.limits.objects {
            return Err(Error::LimitExceeded {
                resource: field,
                actual: value,
                limit: self.limits.objects,
            });
        }
        Ok(value)
    }

    fn read_variable_length(&mut self, index: usize) -> Result<usize> {
        let raw: u64 = self.stream.read_unsigned()?;
        let value: usize = usize::try_from(raw).map_err(|_| Error::InvalidClusterValue {
            index,
            field: "variable length",
            value: i64::MAX,
        })?;
        if value > self.limits.variable_length {
            return Err(Error::LimitExceeded {
                resource: "variable length",
                actual: value,
                limit: self.limits.variable_length,
            });
        }
        Ok(value)
    }

    fn node_mut(&mut self, reference: usize) -> Result<&mut Node> {
        self.nodes
            .get_mut(reference)
            .ok_or_else(|| Error::ReferenceOutOfBounds {
                reference: u32::try_from(reference).unwrap_or(u32::MAX),
                objects: self.object_count,
                offset: self.stream.position(),
            })
    }
}

fn reserve_exact<T>(values: &mut Vec<T>, resource: &'static str, requested: usize) -> Result<()> {
    values
        .try_reserve_exact(requested)
        .map_err(
            |_error: std::collections::TryReserveError| Error::AllocationFailed {
                resource,
                requested,
            },
        )
}

fn push_fallible<T>(values: &mut Vec<T>, value: T, resource: &'static str) -> Result<()> {
    if values.len() == values.capacity() {
        let requested: usize = values.len().checked_add(1).ok_or(Error::AllocationFailed {
            resource,
            requested: usize::MAX,
        })?;
        values
            .try_reserve(1)
            .map_err(
                |_error: std::collections::TryReserveError| Error::AllocationFailed {
                    resource,
                    requested,
                },
            )?;
    }
    values.push(value);
    Ok(())
}

fn decode_one_byte_string(bytes: &[u8]) -> Result<String> {
    let capacity: usize = bytes.len().checked_mul(2).ok_or(Error::AllocationFailed {
        resource: "one-byte string output",
        requested: usize::MAX,
    })?;
    let mut text: String = String::new();
    text.try_reserve_exact(capacity)
        .map_err(
            |_error: std::collections::TryReserveError| Error::AllocationFailed {
                resource: "one-byte string output",
                requested: capacity,
            },
        )?;
    for byte in bytes {
        text.push(char::from(*byte));
    }
    Ok(text)
}

fn decode_two_byte_string(bytes: &[u8]) -> Result<Option<String>> {
    let unit_count: usize = bytes.len() / 2;
    let capacity: usize = unit_count.checked_mul(3).ok_or(Error::AllocationFailed {
        resource: "two-byte string output",
        requested: usize::MAX,
    })?;
    let mut text: String = String::new();
    text.try_reserve_exact(capacity)
        .map_err(
            |_error: std::collections::TryReserveError| Error::AllocationFailed {
                resource: "two-byte string output",
                requested: capacity,
            },
        )?;
    for character in char::decode_utf16(
        bytes
            .chunks_exact(2)
            .map(|pair: &[u8]| u16::from_le_bytes([pair[0], pair[1]])),
    ) {
        let Ok(character): std::result::Result<char, std::char::DecodeUtf16Error> = character
        else {
            return Ok(None);
        };
        text.push(character);
    }
    Ok(Some(text))
}

fn allocation_lengths(cluster: &Cluster) -> Result<&[usize]> {
    match &cluster.allocation {
        AllocationData::Lengths(lengths) => Ok(lengths),
        _ => Err(Error::InvalidClusterValue {
            index: cluster.index,
            field: "allocation lengths",
            value: -1,
        }),
    }
}

const fn node_kind(layout: ClusterLayout) -> NodeKind {
    match layout {
        ClusterLayout::Class => NodeKind::Class,
        ClusterLayout::PatchClass => NodeKind::PatchClass,
        ClusterLayout::Function => NodeKind::Function,
        ClusterLayout::Field => NodeKind::Field,
        ClusterLayout::Library => NodeKind::Library,
        ClusterLayout::String => NodeKind::String,
        ClusterLayout::FunctionType => NodeKind::FunctionType,
        _ => NodeKind::Other,
    }
}

fn to_usize(value: u64, resource: &'static str, limit: usize) -> Result<usize> {
    let converted: usize = usize::try_from(value).map_err(|_| Error::LimitExceeded {
        resource,
        actual: usize::MAX,
        limit,
    })?;
    if converted > limit {
        return Err(Error::LimitExceeded {
            resource,
            actual: converted,
            limit,
        });
    }
    Ok(converted)
}

fn positive_usize(index: usize, field: &'static str, value: i32) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::InvalidClusterValue {
        index,
        field,
        value: i64::from(value),
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_one_byte_string, decode_two_byte_string};
    use crate::Result;

    #[test]
    fn decodes_one_byte_latin1() -> Result<()> {
        let decoded: String = decode_one_byte_string(&[65, 233])?;
        assert_eq!(decoded, "A\u{e9}");
        Ok(())
    }

    #[test]
    fn decodes_two_byte_utf16() -> Result<()> {
        let decoded: Option<String> = decode_two_byte_string(&[65, 0, 61, 216, 0, 222])?;
        assert_eq!(decoded.as_deref(), Some("A\u{1f600}"));
        Ok(())
    }

    #[test]
    fn rejects_unpaired_two_byte_surrogate() -> Result<()> {
        let decoded: Option<String> = decode_two_byte_string(&[61, 216])?;
        assert!(decoded.is_none());
        Ok(())
    }
}
