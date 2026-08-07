use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use serde::{Deserialize, Serialize};

use super::dart_graph::{DartGraphNode, DartGraphNodeKind, DartGraphSnapshotSummary};
use super::dart_graph_layout::{DartClusterBodyKind, DartDeclarationBodyLayouts, DartPinnedLayout};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphInventoryCounts {
    pub libraries: usize,
    pub classes: usize,
    pub methods: usize,
    pub fields: usize,
    pub named_classes: usize,
    pub named_methods: usize,
    pub named_fields: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DartGraphDeclaredObjects {
    pub libraries: usize,
    pub classes: usize,
    pub patch_classes: usize,
    pub functions: usize,
    pub fields: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DartGraphAttributionResidue {
    pub unattributed_classes: usize,
    pub unattributed_methods: usize,
    pub unattributed_fields: usize,
    pub synthesized_libraries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPinnedInventory {
    pub counts: DartGraphInventoryCounts,
    pub declared: DartGraphDeclaredObjects,
    pub residue: DartGraphAttributionResidue,
    pub libraries: Vec<DartPinnedLibraryInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPinnedLibraryInventory {
    pub reference_id: u32,
    pub name: Option<String>,
    pub url: Option<String>,
    pub classes: Vec<DartPinnedClassInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPinnedClassInventory {
    pub reference_id: u32,
    pub class_id: Option<i32>,
    pub name: Option<String>,
    pub methods: Vec<DartPinnedMethodInventory>,
    pub fields: Vec<DartPinnedFieldInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPinnedMethodInventory {
    pub reference_id: u32,
    pub name: Option<String>,
    pub signature: Option<String>,
    pub parameter_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartPinnedFieldInventory {
    pub reference_id: u32,
    pub name: Option<String>,
}

pub(super) fn declared_objects(
    vm: &DartGraphSnapshotSummary,
    isolate: &DartGraphSnapshotSummary,
) -> DartGraphDeclaredObjects {
    DartGraphDeclaredObjects {
        libraries: declared_kind(vm, isolate, DartClusterBodyKind::Library),
        classes: declared_kind(vm, isolate, DartClusterBodyKind::Class),
        patch_classes: declared_kind(vm, isolate, DartClusterBodyKind::PatchClass),
        functions: declared_kind(vm, isolate, DartClusterBodyKind::Function),
        fields: declared_kind(vm, isolate, DartClusterBodyKind::Field),
    }
}

fn declared_kind(
    vm: &DartGraphSnapshotSummary,
    isolate: &DartGraphSnapshotSummary,
    kind: DartClusterBodyKind,
) -> usize {
    cluster_objects(vm, kind).saturating_add(cluster_objects(isolate, kind))
}

fn cluster_objects(summary: &DartGraphSnapshotSummary, kind: DartClusterBodyKind) -> usize {
    summary
        .clusters
        .iter()
        .filter(|cluster: &&super::dart_graph::DartGraphClusterSummary| cluster.kind == kind)
        .fold(
            0_usize,
            |total: usize, cluster: &super::dart_graph::DartGraphClusterSummary| {
                total.saturating_add(cluster.object_count)
            },
        )
}

pub(super) fn build_pinned_inventory(
    nodes: &[DartGraphNode],
    layout: DartPinnedLayout,
    declared: DartGraphDeclaredObjects,
) -> DartPinnedInventory {
    let layouts: DartDeclarationBodyLayouts = layout.declarations;
    let mut libraries: BTreeMap<u32, DartPinnedLibraryInventory> = BTreeMap::new();
    let mut classes: BTreeMap<u32, (u32, DartPinnedClassInventory)> = BTreeMap::new();
    let mut patch_owners: BTreeMap<u32, u32> = BTreeMap::new();
    let mut residue: DartGraphAttributionResidue = DartGraphAttributionResidue::default();

    for (index, node) in nodes.iter().enumerate().skip(1) {
        let reference_id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        if node.kind == DartGraphNodeKind::Library {
            let name: Option<String> = node
                .references
                .get(layouts.library.name_reference)
                .and_then(|reference: &u32| text_at(nodes, *reference))
                .map(str::to_owned);
            let url: Option<String> = node
                .references
                .get(layouts.library.url_reference)
                .and_then(|reference: &u32| text_at(nodes, *reference))
                .map(str::to_owned);
            libraries.insert(
                reference_id,
                DartPinnedLibraryInventory {
                    reference_id,
                    name,
                    url,
                    classes: Vec::new(),
                },
            );
        } else if node.kind == DartGraphNodeKind::PatchClass
            && let Some(wrapped) = node
                .references
                .get(layouts.patch_class.wrapped_class_reference)
                .copied()
        {
            patch_owners.insert(reference_id, wrapped);
        }
    }

    for (index, node) in nodes.iter().enumerate().skip(1) {
        if node.kind != DartGraphNodeKind::Class {
            continue;
        }
        let Some(library_reference): Option<u32> = node
            .references
            .get(layouts.class.library_reference)
            .copied()
        else {
            residue.unattributed_classes = residue.unattributed_classes.saturating_add(1);
            continue;
        };
        let Some(name_reference): Option<u32> =
            node.references.get(layouts.class.name_reference).copied()
        else {
            residue.unattributed_classes = residue.unattributed_classes.saturating_add(1);
            continue;
        };
        let reference_id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
        classes.insert(
            reference_id,
            (
                library_reference,
                DartPinnedClassInventory {
                    reference_id,
                    class_id: node.class_id,
                    name,
                    methods: Vec::new(),
                    fields: Vec::new(),
                },
            ),
        );
    }

    for (index, node) in nodes.iter().enumerate().skip(1) {
        let reference_id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        match node.kind {
            DartGraphNodeKind::Function => {
                let Some(owner_reference): Option<u32> = node
                    .references
                    .get(layouts.function.owner_reference)
                    .copied()
                else {
                    residue.unattributed_methods = residue.unattributed_methods.saturating_add(1);
                    continue;
                };
                let Some(name_reference): Option<u32> = node
                    .references
                    .get(layouts.function.name_reference)
                    .copied()
                else {
                    residue.unattributed_methods = residue.unattributed_methods.saturating_add(1);
                    continue;
                };
                let Some(signature_reference): Option<u32> = node
                    .references
                    .get(layouts.function.signature_reference)
                    .copied()
                else {
                    residue.unattributed_methods = residue.unattributed_methods.saturating_add(1);
                    continue;
                };
                let owner: u32 = resolve_owner(owner_reference, &patch_owners);
                let Some((_library, class)) = classes.get_mut(&owner) else {
                    residue.unattributed_methods = residue.unattributed_methods.saturating_add(1);
                    continue;
                };
                let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
                let parameter_count: Option<usize> = nodes
                    .get(usize::try_from(signature_reference).unwrap_or(usize::MAX))
                    .filter(|signature: &&DartGraphNode| {
                        signature.kind == DartGraphNodeKind::FunctionType
                    })
                    .and_then(|signature: &DartGraphNode| signature.parameter_count);
                let signature: Option<String> = parameter_count.map(format_parameter_count);
                class.methods.push(DartPinnedMethodInventory {
                    reference_id,
                    name,
                    signature,
                    parameter_count,
                });
            }
            DartGraphNodeKind::Field => {
                let Some(owner_reference): Option<u32> =
                    node.references.get(layouts.field.owner_reference).copied()
                else {
                    residue.unattributed_fields = residue.unattributed_fields.saturating_add(1);
                    continue;
                };
                let Some(name_reference): Option<u32> =
                    node.references.get(layouts.field.name_reference).copied()
                else {
                    residue.unattributed_fields = residue.unattributed_fields.saturating_add(1);
                    continue;
                };
                let owner: u32 = resolve_owner(owner_reference, &patch_owners);
                let Some((_library, class)) = classes.get_mut(&owner) else {
                    residue.unattributed_fields = residue.unattributed_fields.saturating_add(1);
                    continue;
                };
                let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
                class
                    .fields
                    .push(DartPinnedFieldInventory { reference_id, name });
            }
            _ => {}
        }
    }

    for (_reference, (library_reference, mut class)) in classes {
        class.methods.sort_by(
            |left: &DartPinnedMethodInventory, right: &DartPinnedMethodInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            },
        );
        class.fields.sort_by(
            |left: &DartPinnedFieldInventory, right: &DartPinnedFieldInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            },
        );
        let library: &mut DartPinnedLibraryInventory = match libraries.entry(library_reference) {
            Entry::Occupied(occupied) => occupied.into_mut(),
            Entry::Vacant(vacant) => {
                residue.synthesized_libraries = residue.synthesized_libraries.saturating_add(1);
                vacant.insert(DartPinnedLibraryInventory {
                    reference_id: library_reference,
                    name: None,
                    url: None,
                    classes: Vec::new(),
                })
            }
        };
        library.classes.push(class);
    }

    let mut library_values: Vec<DartPinnedLibraryInventory> = libraries.into_values().collect();
    for library in &mut library_values {
        library.classes.sort_by(
            |left: &DartPinnedClassInventory, right: &DartPinnedClassInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            },
        );
    }
    library_values.sort_by(
        |left: &DartPinnedLibraryInventory, right: &DartPinnedLibraryInventory| {
            left.url
                .as_deref()
                .cmp(&right.url.as_deref())
                .then(left.reference_id.cmp(&right.reference_id))
        },
    );
    let counts: DartGraphInventoryCounts = count_inventory(&library_values);
    DartPinnedInventory {
        counts,
        declared,
        residue,
        libraries: library_values,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DartGraphNameEvidence {
    Descriptive,
    Opaque,
    Indeterminate,
}

pub(super) fn classify_name_evidence(inventory: &DartPinnedInventory) -> DartGraphNameEvidence {
    let mut considered: usize = 0;
    let mut opaque: usize = 0;
    for library in inventory
        .libraries
        .iter()
        .filter(|library: &&DartPinnedLibraryInventory| {
            is_application_library(library.url.as_deref())
        })
    {
        for class in &library.classes {
            if let Some(name) = class.name.as_deref() {
                record_opacity(name, &mut considered, &mut opaque);
            }
            for method in &class.methods {
                if let Some(name) = method.name.as_deref() {
                    record_opacity(name, &mut considered, &mut opaque);
                }
            }
            for field in &class.fields {
                if let Some(name) = field.name.as_deref() {
                    record_opacity(name, &mut considered, &mut opaque);
                }
            }
        }
    }
    if considered < 6 {
        DartGraphNameEvidence::Indeterminate
    } else if opaque.saturating_mul(5) >= considered.saturating_mul(4) {
        DartGraphNameEvidence::Opaque
    } else if considered.saturating_sub(opaque).saturating_mul(5) >= considered.saturating_mul(4) {
        DartGraphNameEvidence::Descriptive
    } else {
        DartGraphNameEvidence::Indeterminate
    }
}

fn text_at(nodes: &[DartGraphNode], reference: u32) -> Option<&str> {
    let index: usize = usize::try_from(reference).ok()?;
    nodes.get(index)?.text.as_deref()
}

fn resolve_owner(owner: u32, patch_owners: &BTreeMap<u32, u32>) -> u32 {
    patch_owners.get(&owner).copied().unwrap_or(owner)
}

fn format_parameter_count(count: usize) -> String {
    if count == 1 {
        "(1 parameter)".to_owned()
    } else {
        format!("({count} parameters)")
    }
}

fn count_inventory(libraries: &[DartPinnedLibraryInventory]) -> DartGraphInventoryCounts {
    let mut counts: DartGraphInventoryCounts = DartGraphInventoryCounts {
        libraries: libraries.len(),
        classes: 0,
        methods: 0,
        fields: 0,
        named_classes: 0,
        named_methods: 0,
        named_fields: 0,
    };
    for library in libraries {
        counts.classes = counts.classes.saturating_add(library.classes.len());
        for class in &library.classes {
            counts.methods = counts.methods.saturating_add(class.methods.len());
            counts.fields = counts.fields.saturating_add(class.fields.len());
            counts.named_classes = counts
                .named_classes
                .saturating_add(usize::from(class.name.is_some()));
            counts.named_methods = counts.named_methods.saturating_add(
                class
                    .methods
                    .iter()
                    .filter(|method: &&DartPinnedMethodInventory| method.name.is_some())
                    .count(),
            );
            counts.named_fields = counts.named_fields.saturating_add(
                class
                    .fields
                    .iter()
                    .filter(|field: &&DartPinnedFieldInventory| field.name.is_some())
                    .count(),
            );
        }
    }
    counts
}

fn is_application_library(url: Option<&str>) -> bool {
    let Some(value) = url else {
        return false;
    };
    (value.starts_with("package:")
        && !value.starts_with("package:flutter/")
        && !value.starts_with("package:flutter_test/")
        && !value.starts_with("package:sky_engine/"))
        || value.ends_with("/lib/main.dart")
}

fn record_opacity(name: &str, considered: &mut usize, opaque: &mut usize) {
    let token: &str = name
        .strip_prefix("get:")
        .or_else(|| name.strip_prefix("set:"))
        .unwrap_or(name);
    if token.is_empty()
        || token.starts_with('<')
        || matches!(token, "new" | "call" | "toString" | "hashCode")
    {
        return;
    }
    *considered = considered.saturating_add(1);
    if token.len() <= 3 && token.bytes().all(|byte: u8| byte.is_ascii_alphanumeric()) {
        *opaque = opaque.saturating_add(1);
    }
}
