use serde::{Deserialize, Serialize};

use crate::header::{
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH,
};

const FIRST_TYPED_DATA_CID: u32 = 112;
const LAST_TYPED_DATA_CID: u32 = 167;
const TYPED_DATA_VARIANTS: u32 = 4;
const FIRST_FFI_MARKER_CID: u32 = 97;
const LAST_FFI_MARKER_CID: u32 = 109;
const NUM_PREDEFINED_CIDS: u32 = 175;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClusterLayout {
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
pub struct ClusterLayoutEntry {
    pub class_id: u32,
    pub layout: ClusterLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClassDeclarationLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub library_reference: usize,
    pub top_level_class_id_offset: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FunctionDeclarationLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub owner_reference: usize,
    pub signature_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FieldDeclarationLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub owner_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LibraryDeclarationLayout {
    pub reference_count: usize,
    pub name_reference: usize,
    pub url_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PatchClassDeclarationLayout {
    pub reference_count: usize,
    pub wrapped_class_reference: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DeclarationLayouts {
    pub class: ClassDeclarationLayout,
    pub function: FunctionDeclarationLayout,
    pub field: FieldDeclarationLayout,
    pub library: LibraryDeclarationLayout,
    pub patch_class: PatchClassDeclarationLayout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LayoutDescriptor {
    pub snapshot_compatibility_hash: &'static str,
    pub features: &'static str,
    pub clusters: &'static [ClusterLayoutEntry],
    pub first_typed_data_cid: u32,
    pub last_typed_data_cid: u32,
    pub typed_data_variants: u32,
    pub first_ffi_marker_cid: u32,
    pub last_ffi_marker_cid: u32,
    pub num_predefined_cids: u32,
    pub instance_header_words: usize,
    pub word_32_parts: usize,
    pub declarations: DeclarationLayouts,
}

const DART_3_12_2_DECLARATIONS: DeclarationLayouts = DeclarationLayouts {
    class: ClassDeclarationLayout {
        reference_count: 13,
        name_reference: 0,
        library_reference: 7,
        top_level_class_id_offset: 1 << 20,
    },
    function: FunctionDeclarationLayout {
        reference_count: 4,
        name_reference: 0,
        owner_reference: 1,
        signature_reference: 2,
    },
    field: FieldDeclarationLayout {
        reference_count: 4,
        name_reference: 0,
        owner_reference: 1,
    },
    library: LibraryDeclarationLayout {
        reference_count: 10,
        name_reference: 0,
        url_reference: 1,
    },
    patch_class: PatchClassDeclarationLayout {
        reference_count: 2,
        wrapped_class_reference: 0,
    },
};

const DART_3_12_2_CLUSTERS: &[ClusterLayoutEntry] = &[
    ClusterLayoutEntry {
        class_id: 5,
        layout: ClusterLayout::Class,
    },
    ClusterLayoutEntry {
        class_id: 6,
        layout: ClusterLayout::PatchClass,
    },
    ClusterLayoutEntry {
        class_id: 7,
        layout: ClusterLayout::Function,
    },
    ClusterLayoutEntry {
        class_id: 8,
        layout: ClusterLayout::TypeParameters,
    },
    ClusterLayoutEntry {
        class_id: 9,
        layout: ClusterLayout::ClosureData,
    },
    ClusterLayoutEntry {
        class_id: 11,
        layout: ClusterLayout::Field,
    },
    ClusterLayoutEntry {
        class_id: 12,
        layout: ClusterLayout::Script,
    },
    ClusterLayoutEntry {
        class_id: 13,
        layout: ClusterLayout::Library,
    },
    ClusterLayoutEntry {
        class_id: 17,
        layout: ClusterLayout::WeakArray,
    },
    ClusterLayoutEntry {
        class_id: 18,
        layout: ClusterLayout::Code,
    },
    ClusterLayoutEntry {
        class_id: 23,
        layout: ClusterLayout::ObjectPool,
    },
    ClusterLayoutEntry {
        class_id: 24,
        layout: ClusterLayout::PcDescriptors,
    },
    ClusterLayoutEntry {
        class_id: 25,
        layout: ClusterLayout::CodeSourceMap,
    },
    ClusterLayoutEntry {
        class_id: 28,
        layout: ClusterLayout::ExceptionHandlers,
    },
    ClusterLayoutEntry {
        class_id: 35,
        layout: ClusterLayout::UnlinkedCall,
    },
    ClusterLayoutEntry {
        class_id: 38,
        layout: ClusterLayout::SubtypeTestCache,
    },
    ClusterLayoutEntry {
        class_id: 39,
        layout: ClusterLayout::LoadingUnit,
    },
    ClusterLayoutEntry {
        class_id: 45,
        layout: ClusterLayout::Instance,
    },
    ClusterLayoutEntry {
        class_id: 47,
        layout: ClusterLayout::TypeArguments,
    },
    ClusterLayoutEntry {
        class_id: 49,
        layout: ClusterLayout::Type,
    },
    ClusterLayoutEntry {
        class_id: 50,
        layout: ClusterLayout::FunctionType,
    },
    ClusterLayoutEntry {
        class_id: 51,
        layout: ClusterLayout::RecordType,
    },
    ClusterLayoutEntry {
        class_id: 52,
        layout: ClusterLayout::TypeParameter,
    },
    ClusterLayoutEntry {
        class_id: 57,
        layout: ClusterLayout::Closure,
    },
    ClusterLayoutEntry {
        class_id: 61,
        layout: ClusterLayout::Mint,
    },
    ClusterLayoutEntry {
        class_id: 62,
        layout: ClusterLayout::Double,
    },
    ClusterLayoutEntry {
        class_id: 67,
        layout: ClusterLayout::Record,
    },
    ClusterLayoutEntry {
        class_id: 87,
        layout: ClusterLayout::Map,
    },
    ClusterLayoutEntry {
        class_id: 89,
        layout: ClusterLayout::Set,
    },
    ClusterLayoutEntry {
        class_id: 90,
        layout: ClusterLayout::Array,
    },
    ClusterLayoutEntry {
        class_id: 91,
        layout: ClusterLayout::Array,
    },
    ClusterLayoutEntry {
        class_id: 92,
        layout: ClusterLayout::GrowableObjectArray,
    },
    ClusterLayoutEntry {
        class_id: 93,
        layout: ClusterLayout::String,
    },
    ClusterLayoutEntry {
        class_id: 94,
        layout: ClusterLayout::String,
    },
];

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT: LayoutDescriptor = LayoutDescriptor {
    snapshot_compatibility_hash: DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH,
    features: DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    clusters: DART_3_12_2_CLUSTERS,
    first_typed_data_cid: FIRST_TYPED_DATA_CID,
    last_typed_data_cid: LAST_TYPED_DATA_CID,
    typed_data_variants: TYPED_DATA_VARIANTS,
    first_ffi_marker_cid: FIRST_FFI_MARKER_CID,
    last_ffi_marker_cid: LAST_FFI_MARKER_CID,
    num_predefined_cids: NUM_PREDEFINED_CIDS,
    instance_header_words: 2,
    word_32_parts: 2,
    declarations: DART_3_12_2_DECLARATIONS,
};

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT: LayoutDescriptor = LayoutDescriptor {
    snapshot_compatibility_hash: DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH,
    features: DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES,
    clusters: DART_3_12_2_CLUSTERS,
    first_typed_data_cid: FIRST_TYPED_DATA_CID,
    last_typed_data_cid: LAST_TYPED_DATA_CID,
    typed_data_variants: TYPED_DATA_VARIANTS,
    first_ffi_marker_cid: FIRST_FFI_MARKER_CID,
    last_ffi_marker_cid: LAST_FFI_MARKER_CID,
    num_predefined_cids: NUM_PREDEFINED_CIDS,
    instance_header_words: 2,
    word_32_parts: 2,
    declarations: DART_3_12_2_DECLARATIONS,
};

pub const LAYOUT_DESCRIPTORS: &[LayoutDescriptor] = &[
    DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT,
];

#[must_use]
pub fn layout_descriptor(
    snapshot_compatibility_hash: &str,
    features: &str,
) -> Option<LayoutDescriptor> {
    LAYOUT_DESCRIPTORS
        .iter()
        .copied()
        .find(|descriptor: &LayoutDescriptor| {
            descriptor.snapshot_compatibility_hash == snapshot_compatibility_hash
                && descriptor.features == features
        })
}

#[must_use]
pub fn has_layout_compatibility_hash(snapshot_compatibility_hash: &str) -> bool {
    LAYOUT_DESCRIPTORS
        .iter()
        .any(|descriptor: &LayoutDescriptor| {
            descriptor.snapshot_compatibility_hash == snapshot_compatibility_hash
        })
}

impl LayoutDescriptor {
    pub(crate) fn cluster_layout(self, class_id: u32) -> Option<ClusterLayout> {
        if class_id >= self.num_predefined_cids
            || (self.first_ffi_marker_cid..=self.last_ffi_marker_cid).contains(&class_id)
        {
            return Some(ClusterLayout::Instance);
        }
        if (self.first_typed_data_cid..=self.last_typed_data_cid).contains(&class_id)
            && (class_id - self.first_typed_data_cid).is_multiple_of(self.typed_data_variants)
        {
            return Some(ClusterLayout::TypedData);
        }
        self.clusters
            .binary_search_by_key(&class_id, |entry: &ClusterLayoutEntry| entry.class_id)
            .ok()
            .map(|index: usize| self.clusters[index].layout)
    }

    pub(crate) const fn typed_data_element_size(self, class_id: u32) -> Option<usize> {
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
mod tests {
    use super::{ClusterLayout, DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT, LayoutDescriptor};

    #[test]
    fn maps_both_string_class_ids() {
        let descriptor: LayoutDescriptor = DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT;
        assert_eq!(descriptor.cluster_layout(93), Some(ClusterLayout::String));
        assert_eq!(descriptor.cluster_layout(94), Some(ClusterLayout::String));
    }
}
