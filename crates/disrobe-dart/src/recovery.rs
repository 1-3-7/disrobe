use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::graph::{SnapshotRole, SnapshotSummary, parse_graph};
use crate::header::{SnapshotHeader, SupportStatus, parse_snapshot_header, support_status};
use crate::inventory::{
    DartInventory, FieldInventory, InventoryCounts, LibraryInventory, MethodInventory,
    NameEvidence, build_inventory, classify_name_evidence,
};
use crate::layout::{LayoutDescriptor, layout_descriptor};
use crate::limits::RecoveryLimits;
use crate::locator::{DartBlobKind, locate_snapshot_blobs};
use crate::{Error, SnapshotBlob};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObfuscationHint {
    Auto,
    SourceNames,
    OpaqueNames,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOptions {
    pub limits: RecoveryLimits,
    pub obfuscation_hint: ObfuscationHint,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            limits: RecoveryLimits::default(),
            obfuscation_hint: ObfuscationHint::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryStatus {
    Recovered,
    StructureOnly,
    UnsupportedVersion,
    UnsupportedFeatures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NameMode {
    Source,
    Opaque,
    Unclassified,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobSizes {
    pub vm_data: usize,
    pub vm_instructions: usize,
    pub isolate_data: usize,
    pub isolate_instructions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub status: RecoveryStatus,
    pub name_mode: NameMode,
    pub name_mode_reason: String,
    pub snapshot_compatibility_hash: String,
    pub features: String,
    pub blob_sizes: BlobSizes,
    pub vm_snapshot: Option<SnapshotSummary>,
    pub isolate_snapshot: Option<SnapshotSummary>,
    pub inventory: DartInventory,
    pub warnings: Vec<String>,
}

impl RecoveryReport {
    #[must_use]
    pub fn contains_class(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &LibraryInventory| {
                library
                    .classes
                    .iter()
                    .any(|class: &crate::ClassInventory| class.name.as_deref() == Some(expected))
            })
    }

    #[must_use]
    pub fn contains_method(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &LibraryInventory| {
                library.classes.iter().any(|class: &crate::ClassInventory| {
                    class
                        .methods
                        .iter()
                        .any(|method: &MethodInventory| method.name.as_deref() == Some(expected))
                })
            })
    }

    #[must_use]
    pub fn contains_field(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &LibraryInventory| {
                library.classes.iter().any(|class: &crate::ClassInventory| {
                    class
                        .fields
                        .iter()
                        .any(|field: &FieldInventory| field.name.as_deref() == Some(expected))
                })
            })
    }
}

pub fn recover_elf(bytes: &[u8], options: &RecoveryOptions) -> Result<RecoveryReport> {
    let blobs: std::collections::BTreeMap<DartBlobKind, SnapshotBlob<'_>> =
        locate_snapshot_blobs(bytes)?;
    let vm_data: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmData)?;
    let vm_instructions: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmInstructions)?;
    let isolate_data: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::IsolateData)?;
    let isolate_instructions: SnapshotBlob<'_> =
        required_blob(&blobs, DartBlobKind::IsolateInstructions)?;
    recover_data_blobs(
        vm_data.bytes,
        vm_instructions.bytes,
        isolate_data.bytes,
        isolate_instructions.bytes,
        options,
    )
}

pub fn recover_standalone(
    vm_data: &[u8],
    vm_instructions: &[u8],
    isolate_data: &[u8],
    isolate_instructions: &[u8],
    options: &RecoveryOptions,
) -> Result<RecoveryReport> {
    recover_data_blobs(
        vm_data,
        vm_instructions,
        isolate_data,
        isolate_instructions,
        options,
    )
}

fn recover_data_blobs(
    vm_data: &[u8],
    vm_instructions: &[u8],
    isolate_data: &[u8],
    isolate_instructions: &[u8],
    options: &RecoveryOptions,
) -> Result<RecoveryReport> {
    options.limits.validate()?;
    let vm_header: SnapshotHeader = parse_snapshot_header(vm_data)?;
    let isolate_header: SnapshotHeader = parse_snapshot_header(isolate_data)?;
    if vm_header.snapshot_compatibility_hash != isolate_header.snapshot_compatibility_hash {
        return Err(Error::SnapshotHeaderMismatch {
            field: "snapshot compatibility hash",
        });
    }
    if vm_header.features != isolate_header.features {
        return Err(Error::SnapshotHeaderMismatch { field: "features" });
    }
    let blob_sizes: BlobSizes = BlobSizes {
        vm_data: vm_data.len(),
        vm_instructions: vm_instructions.len(),
        isolate_data: isolate_data.len(),
        isolate_instructions: isolate_instructions.len(),
    };
    match support_status(&isolate_header) {
        SupportStatus::UnsupportedVersion => {
            return Ok(unsupported_report(
                RecoveryStatus::UnsupportedVersion,
                "no layout descriptor matches this snapshot compatibility hash",
                &isolate_header,
                blob_sizes,
            ));
        }
        SupportStatus::UnsupportedFeatures => {
            return Ok(unsupported_report(
                RecoveryStatus::UnsupportedFeatures,
                "the known snapshot compatibility hash has a different feature tuple",
                &isolate_header,
                blob_sizes,
            ));
        }
        SupportStatus::Supported => {}
    }
    let Some(descriptor): Option<LayoutDescriptor> = layout_descriptor(
        &isolate_header.snapshot_compatibility_hash,
        &isolate_header.features,
    ) else {
        return Ok(unsupported_report(
            RecoveryStatus::UnsupportedFeatures,
            "the known snapshot compatibility hash has a different feature tuple",
            &isolate_header,
            blob_sizes,
        ));
    };
    let vm_graph: crate::graph::ParsedSnapshot = parse_graph(
        vm_data,
        &vm_header,
        SnapshotRole::Vm,
        None,
        descriptor,
        options.limits,
    )?;
    let isolate_graph: crate::graph::ParsedSnapshot = parse_graph(
        isolate_data,
        &isolate_header,
        SnapshotRole::Isolate,
        Some(&vm_graph.nodes),
        descriptor,
        options.limits,
    )?;
    let inventory: DartInventory = build_inventory(&isolate_graph.nodes, descriptor);
    let (status, name_mode, name_mode_reason): (RecoveryStatus, NameMode, String) =
        classify_names(&inventory, options.obfuscation_hint);
    let warnings: Vec<String> = match name_mode {
        NameMode::Opaque => vec![
            "this crate does not reconstruct identifiers removed by obfuscation; a matching Flutter symbol map can restore them"
                .to_owned(),
        ],
        NameMode::Unclassified => vec![
            "snapshot metadata cannot establish whether identifier obfuscation was used"
                .to_owned(),
        ],
        NameMode::Source | NameMode::Unavailable => Vec::new(),
    };
    Ok(RecoveryReport {
        status,
        name_mode,
        name_mode_reason,
        snapshot_compatibility_hash: isolate_header.snapshot_compatibility_hash,
        features: isolate_header.features,
        blob_sizes,
        vm_snapshot: Some(vm_graph.summary),
        isolate_snapshot: Some(isolate_graph.summary),
        inventory,
        warnings,
    })
}

fn required_blob<'data>(
    blobs: &std::collections::BTreeMap<DartBlobKind, SnapshotBlob<'data>>,
    kind: DartBlobKind,
) -> Result<SnapshotBlob<'data>> {
    blobs
        .get(&kind)
        .copied()
        .ok_or(Error::MissingSnapshotSymbol(match kind {
            DartBlobKind::VmData => "_kDartVmSnapshotData",
            DartBlobKind::VmInstructions => "_kDartVmSnapshotInstructions",
            DartBlobKind::IsolateData => "_kDartIsolateSnapshotData",
            DartBlobKind::IsolateInstructions => "_kDartIsolateSnapshotInstructions",
        }))
}

fn classify_names(
    inventory: &DartInventory,
    hint: ObfuscationHint,
) -> (RecoveryStatus, NameMode, String) {
    match hint {
        ObfuscationHint::SourceNames => (
            RecoveryStatus::Recovered,
            NameMode::Source,
            "caller identified source names".to_owned(),
        ),
        ObfuscationHint::OpaqueNames => (
            RecoveryStatus::StructureOnly,
            NameMode::Opaque,
            "caller identified an obfuscated build".to_owned(),
        ),
        ObfuscationHint::Auto => match classify_name_evidence(inventory) {
            NameEvidence::Opaque => (
                RecoveryStatus::StructureOnly,
                NameMode::Opaque,
                "application declarations have a dominant short-token pattern".to_owned(),
            ),
            NameEvidence::Descriptive => (
                RecoveryStatus::Recovered,
                NameMode::Unclassified,
                "serialized identifiers are descriptive, but build provenance is required to classify source names"
                    .to_owned(),
            ),
            NameEvidence::Indeterminate => (
                RecoveryStatus::Recovered,
                NameMode::Unclassified,
                "serialized identifiers do not provide enough evidence to classify name provenance"
                    .to_owned(),
            ),
        },
    }
}

fn unsupported_report(
    status: RecoveryStatus,
    reason: &str,
    header: &SnapshotHeader,
    blob_sizes: BlobSizes,
) -> RecoveryReport {
    RecoveryReport {
        status,
        name_mode: NameMode::Unavailable,
        name_mode_reason: reason.to_owned(),
        snapshot_compatibility_hash: header.snapshot_compatibility_hash.clone(),
        features: header.features.clone(),
        blob_sizes,
        vm_snapshot: None,
        isolate_snapshot: None,
        inventory: DartInventory {
            counts: InventoryCounts {
                libraries: 0,
                classes: 0,
                methods: 0,
                fields: 0,
                named_classes: 0,
                named_methods: 0,
                named_fields: 0,
            },
            libraries: Vec::new(),
        },
        warnings: vec![reason.to_owned()],
    }
}
