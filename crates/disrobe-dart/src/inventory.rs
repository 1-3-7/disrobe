use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::graph::{Node, NodeKind};
use crate::layout::{DeclarationLayouts, LayoutDescriptor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryCounts {
    pub libraries: usize,
    pub classes: usize,
    pub methods: usize,
    pub fields: usize,
    pub named_classes: usize,
    pub named_methods: usize,
    pub named_fields: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartInventory {
    pub counts: InventoryCounts,
    pub libraries: Vec<LibraryInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryInventory {
    pub reference_id: u32,
    pub name: Option<String>,
    pub url: Option<String>,
    pub classes: Vec<ClassInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassInventory {
    pub reference_id: u32,
    pub class_id: Option<i32>,
    pub name: Option<String>,
    pub methods: Vec<MethodInventory>,
    pub fields: Vec<FieldInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodInventory {
    pub reference_id: u32,
    pub name: Option<String>,
    pub signature: Option<String>,
    pub parameter_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInventory {
    pub reference_id: u32,
    pub name: Option<String>,
}

pub(super) fn build_inventory(nodes: &[Node], descriptor: LayoutDescriptor) -> DartInventory {
    let layouts: DeclarationLayouts = descriptor.declarations;
    let mut libraries: BTreeMap<u32, LibraryInventory> = BTreeMap::new();
    let mut classes: BTreeMap<u32, (u32, ClassInventory)> = BTreeMap::new();
    let mut patch_owners: BTreeMap<u32, u32> = BTreeMap::new();

    for (index, node) in nodes.iter().enumerate().skip(1) {
        let reference_id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        if node.kind == NodeKind::Library {
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
                LibraryInventory {
                    reference_id,
                    name,
                    url,
                    classes: Vec::new(),
                },
            );
        } else if node.kind == NodeKind::PatchClass
            && let Some(wrapped) = node
                .references
                .get(layouts.patch_class.wrapped_class_reference)
                .copied()
        {
            patch_owners.insert(reference_id, wrapped);
        }
    }

    for (index, node) in nodes.iter().enumerate().skip(1) {
        if node.kind != NodeKind::Class {
            continue;
        }
        let Some(library_reference): Option<u32> = node
            .references
            .get(layouts.class.library_reference)
            .copied()
        else {
            continue;
        };
        let Some(name_reference): Option<u32> =
            node.references.get(layouts.class.name_reference).copied()
        else {
            continue;
        };
        let reference_id: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
        classes.insert(
            reference_id,
            (
                library_reference,
                ClassInventory {
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
            NodeKind::Function => {
                let Some(owner_reference): Option<u32> = node
                    .references
                    .get(layouts.function.owner_reference)
                    .copied()
                else {
                    continue;
                };
                let Some(name_reference): Option<u32> = node
                    .references
                    .get(layouts.function.name_reference)
                    .copied()
                else {
                    continue;
                };
                let Some(signature_reference): Option<u32> = node
                    .references
                    .get(layouts.function.signature_reference)
                    .copied()
                else {
                    continue;
                };
                let owner: u32 = resolve_owner(owner_reference, &patch_owners);
                let Some((_library, class)) = classes.get_mut(&owner) else {
                    continue;
                };
                let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
                let parameter_count: Option<usize> = nodes
                    .get(usize::try_from(signature_reference).unwrap_or(usize::MAX))
                    .filter(|signature: &&Node| signature.kind == NodeKind::FunctionType)
                    .and_then(|signature: &Node| signature.parameter_count);
                let signature: Option<String> = parameter_count.map(format_parameter_count);
                class.methods.push(MethodInventory {
                    reference_id,
                    name,
                    signature,
                    parameter_count,
                });
            }
            NodeKind::Field => {
                let Some(owner_reference): Option<u32> =
                    node.references.get(layouts.field.owner_reference).copied()
                else {
                    continue;
                };
                let Some(name_reference): Option<u32> =
                    node.references.get(layouts.field.name_reference).copied()
                else {
                    continue;
                };
                let owner: u32 = resolve_owner(owner_reference, &patch_owners);
                let Some((_library, class)) = classes.get_mut(&owner) else {
                    continue;
                };
                let name: Option<String> = text_at(nodes, name_reference).map(str::to_owned);
                class.fields.push(FieldInventory { reference_id, name });
            }
            _ => {}
        }
    }

    for (_reference, (library_reference, mut class)) in classes {
        class
            .methods
            .sort_by(|left: &MethodInventory, right: &MethodInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            });
        class
            .fields
            .sort_by(|left: &FieldInventory, right: &FieldInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            });
        let library: &mut LibraryInventory =
            libraries
                .entry(library_reference)
                .or_insert_with(|| LibraryInventory {
                    reference_id: library_reference,
                    name: None,
                    url: None,
                    classes: Vec::new(),
                });
        library.classes.push(class);
    }

    let mut library_values: Vec<LibraryInventory> = libraries.into_values().collect();
    for library in &mut library_values {
        library
            .classes
            .sort_by(|left: &ClassInventory, right: &ClassInventory| {
                left.name
                    .as_deref()
                    .cmp(&right.name.as_deref())
                    .then(left.reference_id.cmp(&right.reference_id))
            });
    }
    library_values.sort_by(|left: &LibraryInventory, right: &LibraryInventory| {
        left.url
            .as_deref()
            .cmp(&right.url.as_deref())
            .then(left.reference_id.cmp(&right.reference_id))
    });
    let counts: InventoryCounts = count_inventory(&library_values);
    DartInventory {
        counts,
        libraries: library_values,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NameEvidence {
    Descriptive,
    Opaque,
    Indeterminate,
}

pub(super) fn classify_name_evidence(inventory: &DartInventory) -> NameEvidence {
    let mut considered: usize = 0;
    let mut opaque: usize = 0;
    for library in inventory
        .libraries
        .iter()
        .filter(|library: &&LibraryInventory| is_application_library(library.url.as_deref()))
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
        NameEvidence::Indeterminate
    } else if opaque.saturating_mul(5) >= considered.saturating_mul(4) {
        NameEvidence::Opaque
    } else if considered.saturating_sub(opaque).saturating_mul(5) >= considered.saturating_mul(4) {
        NameEvidence::Descriptive
    } else {
        NameEvidence::Indeterminate
    }
}

fn text_at(nodes: &[Node], reference: u32) -> Option<&str> {
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

fn count_inventory(libraries: &[LibraryInventory]) -> InventoryCounts {
    let mut counts: InventoryCounts = InventoryCounts {
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
                    .filter(|method: &&MethodInventory| method.name.is_some())
                    .count(),
            );
            counts.named_fields = counts.named_fields.saturating_add(
                class
                    .fields
                    .iter()
                    .filter(|field: &&FieldInventory| field.name.is_some())
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
