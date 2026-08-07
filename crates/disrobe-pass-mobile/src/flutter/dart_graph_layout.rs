use serde::{Deserialize, Serialize};

use super::cid_table::{DART_3_12_VERSION_HASH, predefined_count};

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";
pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";

const FIRST_TYPED_DATA_CID: u32 = 112;
const LAST_TYPED_DATA_CID: u32 = 167;
const TYPED_DATA_VARIANTS: u32 = 4;
const FIRST_FFI_MARKER_CID: u32 = 97;
const LAST_FFI_MARKER_CID: u32 = 109;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartClusterBodyKind {
    Array,
    Class,
    Closure,
    ClosureData,
    Code,
    CodeSourceMap,
    Double,
    ExceptionHandlers,
    Field,
    Function,
    FunctionType,
    GrowableObjectArray,
    Instance,
    Library,
    LoadingUnit,
    Map,
    Mint,
    ObjectPool,
    PatchClass,
    PcDescriptors,
    Record,
    RecordType,
    Script,
    Set,
    String,
    SubtypeTestCache,
    Type,
    TypeArguments,
    TypedData,
    TypeParameter,
    TypeParameters,
    UnlinkedCall,
    WeakArray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DartClusterBodyEntry {
    pub class_id: u32,
    pub kind: DartClusterBodyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartClassBodyLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub library_reference: usize,
    pub top_level_class_id_offset: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartFunctionBodyLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub owner_reference: usize,
    pub signature_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartFieldBodyLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub owner_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartLibraryBodyLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub url_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartPatchClassBodyLayout {
    pub reference_count: usize,
    pub wrapped_class_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartDeclarationBodyLayouts {
    pub class: DartClassBodyLayout,
    pub function: DartFunctionBodyLayout,
    pub field: DartFieldBodyLayout,
    pub library: DartLibraryBodyLayout,
    pub patch_class: DartPatchClassBodyLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DartPinnedLayout {
    pub version_hash: &'static str,
    pub features: &'static str,
    pub clusters: &'static [DartClusterBodyEntry],
    pub first_typed_data_cid: u32,
    pub last_typed_data_cid: u32,
    pub typed_data_variants: u32,
    pub first_ffi_marker_cid: u32,
    pub last_ffi_marker_cid: u32,
    pub num_predefined_cids: u32,
    pub instance_header_words: usize,
    pub word_32_parts: usize,
    pub declarations: DartDeclarationBodyLayouts,
}

const DART_3_12_2_DECLARATIONS: DartDeclarationBodyLayouts = DartDeclarationBodyLayouts {
    class: DartClassBodyLayout {
        reference_count: 13,
        name_reference: 0,
        library_reference: 7,
        top_level_class_id_offset: 1 << 20,
    },
    function: DartFunctionBodyLayout {
        reference_count: 4,
        name_reference: 0,
        owner_reference: 1,
        signature_reference: 2,
    },
    field: DartFieldBodyLayout {
        reference_count: 4,
        name_reference: 0,
        owner_reference: 1,
    },
    library: DartLibraryBodyLayout {
        reference_count: 10,
        name_reference: 0,
        url_reference: 1,
    },
    patch_class: DartPatchClassBodyLayout {
        reference_count: 2,
        wrapped_class_reference: 0,
    },
};

const DART_3_12_2_CLUSTERS: &[DartClusterBodyEntry] = &[
    DartClusterBodyEntry {
        class_id: 5,
        kind: DartClusterBodyKind::Class,
    },
    DartClusterBodyEntry {
        class_id: 6,
        kind: DartClusterBodyKind::PatchClass,
    },
    DartClusterBodyEntry {
        class_id: 7,
        kind: DartClusterBodyKind::Function,
    },
    DartClusterBodyEntry {
        class_id: 8,
        kind: DartClusterBodyKind::TypeParameters,
    },
    DartClusterBodyEntry {
        class_id: 9,
        kind: DartClusterBodyKind::ClosureData,
    },
    DartClusterBodyEntry {
        class_id: 11,
        kind: DartClusterBodyKind::Field,
    },
    DartClusterBodyEntry {
        class_id: 12,
        kind: DartClusterBodyKind::Script,
    },
    DartClusterBodyEntry {
        class_id: 13,
        kind: DartClusterBodyKind::Library,
    },
    DartClusterBodyEntry {
        class_id: 17,
        kind: DartClusterBodyKind::WeakArray,
    },
    DartClusterBodyEntry {
        class_id: 18,
        kind: DartClusterBodyKind::Code,
    },
    DartClusterBodyEntry {
        class_id: 23,
        kind: DartClusterBodyKind::ObjectPool,
    },
    DartClusterBodyEntry {
        class_id: 24,
        kind: DartClusterBodyKind::PcDescriptors,
    },
    DartClusterBodyEntry {
        class_id: 25,
        kind: DartClusterBodyKind::CodeSourceMap,
    },
    DartClusterBodyEntry {
        class_id: 28,
        kind: DartClusterBodyKind::ExceptionHandlers,
    },
    DartClusterBodyEntry {
        class_id: 35,
        kind: DartClusterBodyKind::UnlinkedCall,
    },
    DartClusterBodyEntry {
        class_id: 38,
        kind: DartClusterBodyKind::SubtypeTestCache,
    },
    DartClusterBodyEntry {
        class_id: 39,
        kind: DartClusterBodyKind::LoadingUnit,
    },
    DartClusterBodyEntry {
        class_id: 45,
        kind: DartClusterBodyKind::Instance,
    },
    DartClusterBodyEntry {
        class_id: 47,
        kind: DartClusterBodyKind::TypeArguments,
    },
    DartClusterBodyEntry {
        class_id: 49,
        kind: DartClusterBodyKind::Type,
    },
    DartClusterBodyEntry {
        class_id: 50,
        kind: DartClusterBodyKind::FunctionType,
    },
    DartClusterBodyEntry {
        class_id: 51,
        kind: DartClusterBodyKind::RecordType,
    },
    DartClusterBodyEntry {
        class_id: 52,
        kind: DartClusterBodyKind::TypeParameter,
    },
    DartClusterBodyEntry {
        class_id: 57,
        kind: DartClusterBodyKind::Closure,
    },
    DartClusterBodyEntry {
        class_id: 61,
        kind: DartClusterBodyKind::Mint,
    },
    DartClusterBodyEntry {
        class_id: 62,
        kind: DartClusterBodyKind::Double,
    },
    DartClusterBodyEntry {
        class_id: 67,
        kind: DartClusterBodyKind::Record,
    },
    DartClusterBodyEntry {
        class_id: 87,
        kind: DartClusterBodyKind::Map,
    },
    DartClusterBodyEntry {
        class_id: 89,
        kind: DartClusterBodyKind::Set,
    },
    DartClusterBodyEntry {
        class_id: 90,
        kind: DartClusterBodyKind::Array,
    },
    DartClusterBodyEntry {
        class_id: 91,
        kind: DartClusterBodyKind::Array,
    },
    DartClusterBodyEntry {
        class_id: 92,
        kind: DartClusterBodyKind::GrowableObjectArray,
    },
    DartClusterBodyEntry {
        class_id: 93,
        kind: DartClusterBodyKind::String,
    },
    DartClusterBodyEntry {
        class_id: 94,
        kind: DartClusterBodyKind::String,
    },
];

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT: DartPinnedLayout = DartPinnedLayout {
    version_hash: DART_3_12_VERSION_HASH,
    features: DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    clusters: DART_3_12_2_CLUSTERS,
    first_typed_data_cid: FIRST_TYPED_DATA_CID,
    last_typed_data_cid: LAST_TYPED_DATA_CID,
    typed_data_variants: TYPED_DATA_VARIANTS,
    first_ffi_marker_cid: FIRST_FFI_MARKER_CID,
    last_ffi_marker_cid: LAST_FFI_MARKER_CID,
    num_predefined_cids: predefined_count() as u32,
    instance_header_words: 2,
    word_32_parts: 2,
    declarations: DART_3_12_2_DECLARATIONS,
};

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT: DartPinnedLayout = DartPinnedLayout {
    version_hash: DART_3_12_VERSION_HASH,
    features: DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES,
    clusters: DART_3_12_2_CLUSTERS,
    first_typed_data_cid: FIRST_TYPED_DATA_CID,
    last_typed_data_cid: LAST_TYPED_DATA_CID,
    typed_data_variants: TYPED_DATA_VARIANTS,
    first_ffi_marker_cid: FIRST_FFI_MARKER_CID,
    last_ffi_marker_cid: LAST_FFI_MARKER_CID,
    num_predefined_cids: predefined_count() as u32,
    instance_header_words: 2,
    word_32_parts: 2,
    declarations: DART_3_12_2_DECLARATIONS,
};

pub const PINNED_DART_GRAPH_LAYOUTS: &[DartPinnedLayout] = &[
    DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT,
];

#[must_use]
pub fn pinned_dart_graph_layout(version_hash: &str, features: &str) -> Option<DartPinnedLayout> {
    PINNED_DART_GRAPH_LAYOUTS
        .iter()
        .copied()
        .find(|layout: &DartPinnedLayout| {
            layout.version_hash == version_hash && layout.features == features
        })
}

#[must_use]
pub fn has_pinned_dart_graph_layout(version_hash: &str) -> bool {
    PINNED_DART_GRAPH_LAYOUTS
        .iter()
        .any(|layout: &DartPinnedLayout| layout.version_hash == version_hash)
}

impl DartPinnedLayout {
    pub(super) fn cluster_body_kind(self, class_id: u32) -> Option<DartClusterBodyKind> {
        if class_id >= self.num_predefined_cids
            || (self.first_ffi_marker_cid..=self.last_ffi_marker_cid).contains(&class_id)
        {
            return Some(DartClusterBodyKind::Instance);
        }
        if (self.first_typed_data_cid..=self.last_typed_data_cid).contains(&class_id)
            && (class_id - self.first_typed_data_cid).is_multiple_of(self.typed_data_variants)
        {
            return Some(DartClusterBodyKind::TypedData);
        }
        self.clusters
            .binary_search_by_key(&class_id, |entry: &DartClusterBodyEntry| entry.class_id)
            .ok()
            .map(|index: usize| self.clusters[index].kind)
    }

    pub(super) const fn typed_data_element_size(self, class_id: u32) -> Option<usize> {
        if class_id < self.first_typed_data_cid || class_id > self.last_typed_data_cid {
            return None;
        }
        let family: u32 = (class_id - self.first_typed_data_cid) / self.typed_data_variants;
        match family {
            0..=2 => Some(1),
            3..=4 => Some(2),
            5..=6 | 9 => Some(4),
            7..=8 | 10 => Some(8),
            11..=13 => Some(16),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT, DartClusterBodyKind, DartPinnedLayout,
        has_pinned_dart_graph_layout, pinned_dart_graph_layout,
    };
    use crate::flutter::cid_table::DART_3_12_VERSION_HASH;

    #[test]
    fn maps_both_string_class_ids() {
        let layout: DartPinnedLayout = DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT;
        assert_eq!(
            layout.cluster_body_kind(93),
            Some(DartClusterBodyKind::String)
        );
        assert_eq!(
            layout.cluster_body_kind(94),
            Some(DartClusterBodyKind::String)
        );
    }

    #[test]
    fn num_predefined_cids_matches_the_cid_table() {
        assert_eq!(
            DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT.num_predefined_cids,
            u32::from(crate::flutter::cid_table::predefined_count())
        );
    }

    #[test]
    fn unknown_hash_has_no_pinned_layout() {
        assert!(!has_pinned_dart_graph_layout("deadbeef"));
        assert!(has_pinned_dart_graph_layout(DART_3_12_VERSION_HASH));
    }

    #[test]
    fn known_hash_with_unknown_features_is_unsupported() {
        assert!(pinned_dart_graph_layout(DART_3_12_VERSION_HASH, "unknown-features").is_none());
    }
}
