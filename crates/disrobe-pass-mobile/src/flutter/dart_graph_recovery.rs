use serde::{Deserialize, Serialize};

use super::dart_graph::{
    DartGraphLimits, DartGraphSnapshotRole, DartGraphSnapshotSummary, DartParsedGraph,
    parse_dart_graph,
};
use super::dart_graph_inventory::{
    DartGraphAttributionResidue, DartGraphDeclaredObjects, DartGraphInventoryCounts,
    DartGraphNameEvidence, DartPinnedFieldInventory, DartPinnedInventory,
    DartPinnedLibraryInventory, DartPinnedMethodInventory, build_pinned_inventory,
    classify_name_evidence, declared_objects,
};
use super::dart_graph_layout::{
    DartPinnedLayout, has_pinned_dart_graph_layout, pinned_dart_graph_layout,
};
use super::{LibAppLayout, SnapshotSection};
use crate::error::{Error, Result};

const FIXED_HEADER_SIZE: usize = 52;
const MAGIC_SIZE: i64 = 4;
const FEATURE_STRING_CAP: usize = 4096;
const SNAPSHOT_KIND_FULL_AOT: i64 = 3;

struct DartPinnedHeader {
    declared_length: usize,
    snapshot_compatibility_hash: String,
    features: String,
    clustered_offset: usize,
}

fn parse_pinned_header(bytes: &[u8]) -> Result<DartPinnedHeader> {
    if bytes.len() < FIXED_HEADER_SIZE {
        return Err(Error::DartGraphTruncated {
            offset: bytes.len(),
            resource: "snapshot header",
        });
    }
    let magic_bytes: [u8; 4] = bytes[0..4]
        .try_into()
        .map_err(|_: std::array::TryFromSliceError| Error::DartBadMagic)?;
    let magic: u32 = u32::from_le_bytes(magic_bytes);
    if magic != super::DART_SNAPSHOT_MAGIC {
        return Err(Error::DartBadMagic);
    }
    let length_bytes: [u8; 8] =
        bytes[4..12]
            .try_into()
            .map_err(
                |_: std::array::TryFromSliceError| Error::DartGraphInvalidHeader {
                    offset: 4,
                    reason: "declared length is truncated",
                },
            )?;
    let stored_length: i64 = i64::from_le_bytes(length_bytes);
    let declared_i64: i64 =
        stored_length
            .checked_add(MAGIC_SIZE)
            .ok_or(Error::DartGraphInvalidHeader {
                offset: 4,
                reason: "declared length overflows",
            })?;
    let declared_length: usize =
        usize::try_from(declared_i64).map_err(|_: std::num::TryFromIntError| {
            Error::DartGraphInvalidHeader {
                offset: 4,
                reason: "declared length is negative",
            }
        })?;
    if declared_length < FIXED_HEADER_SIZE || declared_length > bytes.len() {
        return Err(Error::DartGraphDeclaredLengthOutOfBounds {
            declared: declared_length,
            available: bytes.len(),
        });
    }
    let kind_bytes: [u8; 8] =
        bytes[12..20]
            .try_into()
            .map_err(
                |_: std::array::TryFromSliceError| Error::DartGraphInvalidHeader {
                    offset: 12,
                    reason: "snapshot kind is truncated",
                },
            )?;
    let kind_raw: i64 = i64::from_le_bytes(kind_bytes);
    if kind_raw != SNAPSHOT_KIND_FULL_AOT {
        return Err(Error::DartGraphInvalidHeader {
            offset: 12,
            reason: "snapshot kind is not full aot",
        });
    }
    let version_bytes: &[u8] = &bytes[20..FIXED_HEADER_SIZE];
    if version_bytes.len() != 32 || !version_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::DartGraphInvalidHeader {
            offset: 20,
            reason: "snapshot compatibility hash is not 32 hex bytes",
        });
    }
    let snapshot_compatibility_hash: String = std::str::from_utf8(version_bytes)
        .map_err(|_: std::str::Utf8Error| Error::DartGraphInvalidHeader {
            offset: 20,
            reason: "snapshot compatibility hash is not utf-8",
        })?
        .to_ascii_lowercase();
    let feature_limit: usize =
        declared_length.min(FIXED_HEADER_SIZE.checked_add(FEATURE_STRING_CAP).ok_or(
            Error::DartGraphInvalidHeader {
                offset: FIXED_HEADER_SIZE,
                reason: "feature string cap overflows",
            },
        )?);
    let feature_region: &[u8] = &bytes[FIXED_HEADER_SIZE..feature_limit];
    let terminator: usize = feature_region
        .iter()
        .position(|value: &u8| *value == 0)
        .ok_or_else(|| {
            if declared_length.saturating_sub(FIXED_HEADER_SIZE) > FEATURE_STRING_CAP {
                Error::DartGraphInvalidHeader {
                    offset: FIXED_HEADER_SIZE,
                    reason: "feature string exceeds the cap",
                }
            } else {
                Error::DartGraphInvalidHeader {
                    offset: FIXED_HEADER_SIZE,
                    reason: "feature string is not nul terminated",
                }
            }
        })?;
    let features: String = std::str::from_utf8(&feature_region[..terminator])
        .map_err(|_: std::str::Utf8Error| Error::DartGraphInvalidHeader {
            offset: FIXED_HEADER_SIZE,
            reason: "feature string is not utf-8",
        })?
        .to_owned();
    let clustered_offset: usize = FIXED_HEADER_SIZE
        .checked_add(terminator)
        .and_then(|value: usize| value.checked_add(1))
        .ok_or(Error::DartGraphInvalidHeader {
            offset: FIXED_HEADER_SIZE,
            reason: "clustered offset overflows",
        })?;
    Ok(DartPinnedHeader {
        declared_length,
        snapshot_compatibility_hash,
        features,
        clustered_offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartGraphObfuscationHint {
    Auto,
    SourceNames,
    OpaqueNames,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphRecoveryOptions {
    pub limits: DartGraphLimits,
    pub obfuscation_hint: DartGraphObfuscationHint,
}

impl Default for DartGraphRecoveryOptions {
    fn default() -> Self {
        Self {
            limits: DartGraphLimits::default(),
            obfuscation_hint: DartGraphObfuscationHint::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartGraphRecoveryStatus {
    Recovered,
    StructureOnly,
    UnsupportedVersion,
    UnsupportedFeatures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartGraphNameMode {
    Source,
    Opaque,
    Unclassified,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphBlobSizes {
    pub vm_data: usize,
    pub vm_instructions: usize,
    pub isolate_data: usize,
    pub isolate_instructions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartGraphRecoveryReport {
    pub status: DartGraphRecoveryStatus,
    pub name_mode: DartGraphNameMode,
    pub name_mode_reason: String,
    pub snapshot_compatibility_hash: String,
    pub features: String,
    pub blob_sizes: DartGraphBlobSizes,
    pub vm_snapshot: Option<DartGraphSnapshotSummary>,
    pub isolate_snapshot: Option<DartGraphSnapshotSummary>,
    pub inventory: DartPinnedInventory,
    pub warnings: Vec<String>,
}

impl DartGraphRecoveryReport {
    #[must_use]
    pub fn contains_class(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &DartPinnedLibraryInventory| {
                library.classes.iter().any(
                    |class: &super::dart_graph_inventory::DartPinnedClassInventory| {
                        class.name.as_deref() == Some(expected)
                    },
                )
            })
    }

    #[must_use]
    pub fn contains_method(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &DartPinnedLibraryInventory| {
                library.classes.iter().any(
                    |class: &super::dart_graph_inventory::DartPinnedClassInventory| {
                        class
                            .methods
                            .iter()
                            .any(|method: &DartPinnedMethodInventory| {
                                method.name.as_deref() == Some(expected)
                            })
                    },
                )
            })
    }

    #[must_use]
    pub fn contains_field(&self, expected: &str) -> bool {
        self.inventory
            .libraries
            .iter()
            .any(|library: &DartPinnedLibraryInventory| {
                library.classes.iter().any(
                    |class: &super::dart_graph_inventory::DartPinnedClassInventory| {
                        class.fields.iter().any(|field: &DartPinnedFieldInventory| {
                            field.name.as_deref() == Some(expected)
                        })
                    },
                )
            })
    }
}

pub fn recover_dart_pinned_elf(
    bytes: &[u8],
    options: &DartGraphRecoveryOptions,
) -> Result<DartGraphRecoveryReport> {
    let layout: LibAppLayout = super::parse_libapp_so(bytes)?;
    require_snapshot_section(layout.vm_snapshot_data.as_ref(), "_kDartVmSnapshotData")?;
    require_snapshot_section(
        layout.vm_snapshot_instructions.as_ref(),
        "_kDartVmSnapshotInstructions",
    )?;
    require_snapshot_section(
        layout.isolate_snapshot_data.as_ref(),
        "_kDartIsolateSnapshotData",
    )?;
    require_snapshot_section(
        layout.isolate_snapshot_instructions.as_ref(),
        "_kDartIsolateSnapshotInstructions",
    )?;
    let vm_data: Vec<u8> = super::vm_data_bytes(bytes)?;
    let isolate_data: Vec<u8> = super::isolate_data_bytes(bytes)?;
    let vm_instructions_len: usize = layout
        .vm_snapshot_instructions
        .as_ref()
        .map_or(0, |section: &SnapshotSection| section.size as usize);
    let isolate_instructions_len: usize = layout
        .isolate_snapshot_instructions
        .as_ref()
        .map_or(0, |section: &SnapshotSection| section.size as usize);
    recover_pinned_data_blobs(
        &vm_data,
        vm_instructions_len,
        &isolate_data,
        isolate_instructions_len,
        options,
    )
}

pub fn recover_dart_pinned_standalone(
    vm_data: &[u8],
    vm_instructions: &[u8],
    isolate_data: &[u8],
    isolate_instructions: &[u8],
    options: &DartGraphRecoveryOptions,
) -> Result<DartGraphRecoveryReport> {
    recover_pinned_data_blobs(
        vm_data,
        vm_instructions.len(),
        isolate_data,
        isolate_instructions.len(),
        options,
    )
}

fn require_snapshot_section(section: Option<&SnapshotSection>, symbol: &'static str) -> Result<()> {
    if section.is_some() {
        Ok(())
    } else {
        Err(Error::DartSectionMissing(symbol))
    }
}

fn recover_pinned_data_blobs(
    vm_data: &[u8],
    vm_instructions_len: usize,
    isolate_data: &[u8],
    isolate_instructions_len: usize,
    options: &DartGraphRecoveryOptions,
) -> Result<DartGraphRecoveryReport> {
    options.limits.validate()?;
    let vm_header: DartPinnedHeader = parse_pinned_header(vm_data)?;
    let isolate_header: DartPinnedHeader = parse_pinned_header(isolate_data)?;
    if vm_header.snapshot_compatibility_hash != isolate_header.snapshot_compatibility_hash {
        return Err(Error::DartGraphHeaderMismatch {
            field: "snapshot compatibility hash",
        });
    }
    if vm_header.features != isolate_header.features {
        return Err(Error::DartGraphHeaderMismatch { field: "features" });
    }
    let blob_sizes: DartGraphBlobSizes = DartGraphBlobSizes {
        vm_data: vm_data.len(),
        vm_instructions: vm_instructions_len,
        isolate_data: isolate_data.len(),
        isolate_instructions: isolate_instructions_len,
    };
    if !has_pinned_dart_graph_layout(&isolate_header.snapshot_compatibility_hash) {
        return Ok(unsupported_report(
            DartGraphRecoveryStatus::UnsupportedVersion,
            "no pinned dart graph layout matches this snapshot compatibility hash",
            &isolate_header,
            blob_sizes,
        ));
    }
    let Some(layout): Option<DartPinnedLayout> = pinned_dart_graph_layout(
        &isolate_header.snapshot_compatibility_hash,
        &isolate_header.features,
    ) else {
        return Ok(unsupported_report(
            DartGraphRecoveryStatus::UnsupportedFeatures,
            "the known snapshot compatibility hash has a different feature tuple",
            &isolate_header,
            blob_sizes,
        ));
    };
    let vm_graph: DartParsedGraph = parse_dart_graph(
        vm_data,
        vm_header.declared_length,
        vm_header.clustered_offset,
        DartGraphSnapshotRole::Vm,
        None,
        layout,
        options.limits,
    )?;
    let isolate_graph: DartParsedGraph = parse_dart_graph(
        isolate_data,
        isolate_header.declared_length,
        isolate_header.clustered_offset,
        DartGraphSnapshotRole::Isolate,
        Some(&vm_graph.nodes),
        layout,
        options.limits,
    )?;
    let declared: DartGraphDeclaredObjects =
        declared_objects(&vm_graph.summary, &isolate_graph.summary);
    let inventory: DartPinnedInventory =
        build_pinned_inventory(&isolate_graph.nodes, layout, declared);
    let (status, name_mode, name_mode_reason): (
        DartGraphRecoveryStatus,
        DartGraphNameMode,
        String,
    ) = classify_names(&inventory, options.obfuscation_hint);
    let warnings: Vec<String> = match name_mode {
        DartGraphNameMode::Opaque => vec![
            "this recovery path does not reconstruct identifiers removed by obfuscation; a matching Flutter symbol map can restore them"
                .to_owned(),
        ],
        DartGraphNameMode::Unclassified => vec![
            "snapshot metadata cannot establish whether identifier obfuscation was used"
                .to_owned(),
        ],
        DartGraphNameMode::Source | DartGraphNameMode::Unavailable => Vec::new(),
    };
    Ok(DartGraphRecoveryReport {
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

fn classify_names(
    inventory: &DartPinnedInventory,
    hint: DartGraphObfuscationHint,
) -> (DartGraphRecoveryStatus, DartGraphNameMode, String) {
    match hint {
        DartGraphObfuscationHint::SourceNames => (
            DartGraphRecoveryStatus::Recovered,
            DartGraphNameMode::Source,
            "caller identified source names".to_owned(),
        ),
        DartGraphObfuscationHint::OpaqueNames => (
            DartGraphRecoveryStatus::StructureOnly,
            DartGraphNameMode::Opaque,
            "caller identified an obfuscated build".to_owned(),
        ),
        DartGraphObfuscationHint::Auto => match classify_name_evidence(inventory) {
            DartGraphNameEvidence::Opaque => (
                DartGraphRecoveryStatus::StructureOnly,
                DartGraphNameMode::Opaque,
                "application declarations have a dominant short-token pattern".to_owned(),
            ),
            DartGraphNameEvidence::Descriptive => (
                DartGraphRecoveryStatus::Recovered,
                DartGraphNameMode::Unclassified,
                "serialized identifiers are descriptive, but build provenance is required to classify source names"
                    .to_owned(),
            ),
            DartGraphNameEvidence::Indeterminate => (
                DartGraphRecoveryStatus::Recovered,
                DartGraphNameMode::Unclassified,
                "serialized identifiers do not provide enough evidence to classify name provenance"
                    .to_owned(),
            ),
        },
    }
}

fn unsupported_report(
    status: DartGraphRecoveryStatus,
    reason: &str,
    header: &DartPinnedHeader,
    blob_sizes: DartGraphBlobSizes,
) -> DartGraphRecoveryReport {
    DartGraphRecoveryReport {
        status,
        name_mode: DartGraphNameMode::Unavailable,
        name_mode_reason: reason.to_owned(),
        snapshot_compatibility_hash: header.snapshot_compatibility_hash.clone(),
        features: header.features.clone(),
        blob_sizes,
        vm_snapshot: None,
        isolate_snapshot: None,
        inventory: DartPinnedInventory {
            counts: DartGraphInventoryCounts {
                libraries: 0,
                classes: 0,
                methods: 0,
                fields: 0,
                named_classes: 0,
                named_methods: 0,
                named_fields: 0,
            },
            declared: DartGraphDeclaredObjects::default(),
            residue: DartGraphAttributionResidue::default(),
            libraries: Vec::new(),
        },
        warnings: vec![reason.to_owned()],
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{DartPinnedHeader, parse_pinned_header};
    use crate::error::Error;
    use crate::flutter::dart_graph_layout::{
        DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES, DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
    };
    use crate::flutter::has_pinned_dart_graph_layout;

    fn snapshot_header(
        snapshot_compatibility_hash: &str,
        features: &str,
    ) -> std::result::Result<Vec<u8>, std::num::TryFromIntError> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&super::super::DART_SNAPSHOT_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&0_i64.to_le_bytes());
        bytes.extend_from_slice(&super::SNAPSHOT_KIND_FULL_AOT.to_le_bytes());
        bytes.extend_from_slice(snapshot_compatibility_hash.as_bytes());
        bytes.extend_from_slice(features.as_bytes());
        bytes.push(0);
        let stored_length: i64 = i64::try_from(bytes.len() - 4)?;
        bytes[4..12].copy_from_slice(&stored_length.to_le_bytes());
        Ok(bytes)
    }

    #[test]
    fn parses_pinned_full_aot_header() {
        let bytes: Vec<u8> = snapshot_header(
            DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT.version_hash,
            DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
        )
        .expect("length fits i64");
        let header: DartPinnedHeader = parse_pinned_header(&bytes).expect("parses");
        assert_eq!(header.declared_length, bytes.len());
        assert_eq!(
            header.snapshot_compatibility_hash,
            DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT.version_hash
        );
        assert_eq!(header.features, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES);
        assert!(has_pinned_dart_graph_layout(
            &header.snapshot_compatibility_hash
        ));
    }

    #[test]
    fn rejects_unknown_version_before_layout_reads() {
        let bytes: Vec<u8> = snapshot_header(
            "0123456789abcdef0123456789abcdef",
            "product arm64 android compressed-pointers",
        )
        .expect("length fits i64");
        let header: DartPinnedHeader = parse_pinned_header(&bytes).expect("parses");
        assert!(!has_pinned_dart_graph_layout(
            &header.snapshot_compatibility_hash
        ));
    }

    #[test]
    fn rejects_non_hex_snapshot_compatibility_hash() {
        let bytes: Vec<u8> = snapshot_header(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "product arm64 android compressed-pointers",
        )
        .expect("length fits i64");
        let result: Result<DartPinnedHeader, Error> = parse_pinned_header(&bytes);
        assert!(matches!(
            result,
            Err(Error::DartGraphInvalidHeader { offset: 20, .. })
        ));
    }

    #[test]
    fn rejects_unterminated_features() {
        let mut bytes: Vec<u8> = snapshot_header(
            DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT.version_hash,
            "product arm64 android compressed-pointers",
        )
        .expect("length fits i64");
        let removed: Option<u8> = bytes.pop();
        assert_eq!(removed, Some(0));
        let stored_length: i64 = i64::try_from(bytes.len() - 4).expect("length fits i64");
        bytes[4..12].copy_from_slice(&stored_length.to_le_bytes());
        let result: Result<DartPinnedHeader, Error> = parse_pinned_header(&bytes);
        assert!(matches!(
            result,
            Err(Error::DartGraphInvalidHeader {
                reason: "feature string is not nul terminated",
                ..
            })
        ));
    }

    #[test]
    fn rejects_declared_length_outside_input() {
        let mut bytes: Vec<u8> = snapshot_header(
            DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT.version_hash,
            "product arm64 android compressed-pointers",
        )
        .expect("length fits i64");
        bytes[4..12].copy_from_slice(&4096_i64.to_le_bytes());
        let result: Result<DartPinnedHeader, Error> = parse_pinned_header(&bytes);
        assert!(matches!(
            result,
            Err(Error::DartGraphDeclaredLengthOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_every_truncated_fixed_header() {
        let bytes: [u8; 52] = [0; 52];
        for length in 0..52 {
            let result: Result<DartPinnedHeader, Error> = parse_pinned_header(&bytes[..length]);
            assert!(matches!(result, Err(Error::DartGraphTruncated { .. })));
        }
    }
}
