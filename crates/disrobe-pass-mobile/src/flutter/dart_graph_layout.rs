use serde::{Deserialize, Serialize};

use super::cid_table::{
    DART_3_3_CLASS_IDS, DART_3_4_CLASS_IDS, DART_3_6_CLASS_IDS, DART_3_9_CLASS_IDS,
    DART_3_12_VERSION_HASH, DartClassIdTable,
};

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";
pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode dedup_instructions no-asan no-msan no-tsan no-shared_data arm64 android compressed-pointers";

const DART_3_3_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode no-lazy_dispatchers dedup_instructions no-tsan no-asserts arm64 android compressed-pointers null-safety";
const DART_3_3_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode no-lazy_dispatchers dedup_instructions no-tsan no-asserts arm64 android compressed-pointers null-safety";
const DART_3_5_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-tsan no-msan arm64 android compressed-pointers";
const DART_3_5_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode dedup_instructions no-tsan no-msan arm64 android compressed-pointers";
const DART_3_9_PRODUCT_FEATURES: &str = "product no-code_comments no-dwarf_stack_traces_mode dedup_instructions no-tsan no-msan no-shared_data arm64 android compressed-pointers";
const DART_3_9_PRODUCT_DWARF_FEATURES: &str = "product no-code_comments dwarf_stack_traces_mode dedup_instructions no-tsan no-msan no-shared_data arm64 android compressed-pointers";

const TOP_LEVEL_CLASS_ID_OFFSET: i32 = 1 << 20;
const IMMUTABLE_TAG_BIT: u32 = 6;
const DEEPLY_IMMUTABLE_TAG_BIT: u32 = 7;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DartClusterTagEncoding {
    ClassIdAndCanonical,
    ObjectTags { immutable_bit: u32 },
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
    pub kind_bits_width: u32,
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
pub struct DartCodeTableLayout {
    pub object_header_bytes: usize,
    pub descriptor_bytes: usize,
    pub entry_stride: usize,
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
    pub class_ids: DartClassIdTable,
    pub cluster_tags: DartClusterTagEncoding,
    pub loading_unit_id_width: u32,
    pub instance_header_words: usize,
    pub word_32_parts: usize,
    pub declarations: DartDeclarationBodyLayouts,
    pub code_table: DartCodeTableLayout,
}

#[derive(Debug, Clone, Copy)]
struct DartRelease {
    version_hash: &'static str,
    class_ids: DartClassIdTable,
    cluster_tags: DartClusterTagEncoding,
    field_kind_bits_width: u32,
    loading_unit_id_width: u32,
}

const DART_3_3: DartRelease = DartRelease {
    version_hash: "ee1eb666c76a5cb7746faf39d0b97547",
    class_ids: DART_3_3_CLASS_IDS,
    cluster_tags: DartClusterTagEncoding::ClassIdAndCanonical,
    field_kind_bits_width: 16,
    loading_unit_id_width: 32,
};

const DART_3_4: DartRelease = DartRelease {
    version_hash: "d20a1be77c3d3c41b2a5accaee1ce549",
    class_ids: DART_3_4_CLASS_IDS,
    cluster_tags: DartClusterTagEncoding::ObjectTags {
        immutable_bit: IMMUTABLE_TAG_BIT,
    },
    field_kind_bits_width: 16,
    loading_unit_id_width: 32,
};

const DART_3_5: DartRelease = DartRelease {
    version_hash: "80a49c7111088100a233b2ae788e1f48",
    loading_unit_id_width: 64,
    ..DART_3_4
};

const DART_3_6: DartRelease = DartRelease {
    version_hash: "f956f595844a2f845a55707faaaa51e4",
    class_ids: DART_3_6_CLASS_IDS,
    ..DART_3_5
};

const DART_3_7: DartRelease = DartRelease {
    version_hash: "d91c0e6f35f0eb2e44124e8f42aa44a7",
    ..DART_3_6
};

const DART_3_8: DartRelease = DartRelease {
    version_hash: "830f4f59e7969c70b595182826435c19",
    ..DART_3_6
};

const DART_3_9: DartRelease = DartRelease {
    version_hash: "97ff04a728735e6b6b098bdf983faaba",
    class_ids: DART_3_9_CLASS_IDS,
    ..DART_3_6
};

const DART_3_10: DartRelease = DartRelease {
    version_hash: "1ce86630892e2dca9a8543fdb8ed8e22",
    field_kind_bits_width: 32,
    ..DART_3_9
};

const DART_3_11: DartRelease = DartRelease {
    version_hash: "78da37fed6bf1489361a312568249f3f",
    ..DART_3_10
};

const DART_3_12: DartRelease = DartRelease {
    version_hash: DART_3_12_VERSION_HASH,
    cluster_tags: DartClusterTagEncoding::ObjectTags {
        immutable_bit: DEEPLY_IMMUTABLE_TAG_BIT,
    },
    ..DART_3_11
};

const DART_CODE_TABLE: DartCodeTableLayout = DartCodeTableLayout {
    object_header_bytes: 20,
    descriptor_bytes: 12,
    entry_stride: 8,
};

const fn declarations(field_kind_bits_width: u32) -> DartDeclarationBodyLayouts {
    DartDeclarationBodyLayouts {
        class: DartClassBodyLayout {
            reference_count: 13,
            name_reference: 0,
            library_reference: 7,
            top_level_class_id_offset: TOP_LEVEL_CLASS_ID_OFFSET,
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
            kind_bits_width: field_kind_bits_width,
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
    }
}

const fn pinned(release: DartRelease, features: &'static str) -> DartPinnedLayout {
    DartPinnedLayout {
        version_hash: release.version_hash,
        features,
        class_ids: release.class_ids,
        cluster_tags: release.cluster_tags,
        loading_unit_id_width: release.loading_unit_id_width,
        instance_header_words: 2,
        word_32_parts: 2,
        declarations: declarations(release.field_kind_bits_width),
        code_table: DART_CODE_TABLE,
    }
}

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT: DartPinnedLayout =
    pinned(DART_3_12, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES);

pub const DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT: DartPinnedLayout =
    pinned(DART_3_12, DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES);

pub const PINNED_DART_GRAPH_LAYOUTS: &[DartPinnedLayout] = &[
    DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT,
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_LAYOUT,
    pinned(DART_3_11, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES),
    pinned(DART_3_11, DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_10, DART_3_9_PRODUCT_FEATURES),
    pinned(DART_3_10, DART_3_9_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_9, DART_3_9_PRODUCT_FEATURES),
    pinned(DART_3_9, DART_3_9_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_8, DART_3_5_PRODUCT_FEATURES),
    pinned(DART_3_8, DART_3_5_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_7, DART_3_5_PRODUCT_FEATURES),
    pinned(DART_3_7, DART_3_5_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_6, DART_3_5_PRODUCT_FEATURES),
    pinned(DART_3_6, DART_3_5_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_5, DART_3_5_PRODUCT_FEATURES),
    pinned(DART_3_5, DART_3_5_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_4, DART_3_3_PRODUCT_FEATURES),
    pinned(DART_3_4, DART_3_3_PRODUCT_DWARF_FEATURES),
    pinned(DART_3_3, DART_3_3_PRODUCT_FEATURES),
    pinned(DART_3_3, DART_3_3_PRODUCT_DWARF_FEATURES),
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
    #[must_use]
    pub fn class_id(self, name: &str) -> Option<u32> {
        self.class_ids.cid(name).map(u32::from)
    }

    pub(super) fn cluster_body_kind(self, class_id: u32) -> Option<DartClusterBodyKind> {
        if class_id >= u32::from(self.class_ids.predefined_count()) {
            return Some(DartClusterBodyKind::Instance);
        }
        let name: &str = self.class_ids.name(u16::try_from(class_id).ok()?)?;
        if typed_data_element_bytes(name).is_some() {
            return Some(DartClusterBodyKind::TypedData);
        }
        let kind: DartClusterBodyKind = match name {
            "Class" => DartClusterBodyKind::Class,
            "PatchClass" => DartClusterBodyKind::PatchClass,
            "Function" => DartClusterBodyKind::Function,
            "TypeParameters" => DartClusterBodyKind::TypeParameters,
            "ClosureData" => DartClusterBodyKind::ClosureData,
            "Field" => DartClusterBodyKind::Field,
            "Script" => DartClusterBodyKind::Script,
            "Library" => DartClusterBodyKind::Library,
            "WeakArray" => DartClusterBodyKind::WeakArray,
            "Code" => DartClusterBodyKind::Code,
            "ObjectPool" => DartClusterBodyKind::ObjectPool,
            "PcDescriptors" => DartClusterBodyKind::PcDescriptors,
            "CodeSourceMap" => DartClusterBodyKind::CodeSourceMap,
            "ExceptionHandlers" => DartClusterBodyKind::ExceptionHandlers,
            "UnlinkedCall" => DartClusterBodyKind::UnlinkedCall,
            "SubtypeTestCache" => DartClusterBodyKind::SubtypeTestCache,
            "LoadingUnit" => DartClusterBodyKind::LoadingUnit,
            "TypeArguments" => DartClusterBodyKind::TypeArguments,
            "Type" => DartClusterBodyKind::Type,
            "FunctionType" => DartClusterBodyKind::FunctionType,
            "RecordType" => DartClusterBodyKind::RecordType,
            "TypeParameter" => DartClusterBodyKind::TypeParameter,
            "Closure" => DartClusterBodyKind::Closure,
            "Mint" => DartClusterBodyKind::Mint,
            "Double" => DartClusterBodyKind::Double,
            "Record" => DartClusterBodyKind::Record,
            "ConstMap" => DartClusterBodyKind::Map,
            "ConstSet" => DartClusterBodyKind::Set,
            "Array" | "ImmutableArray" => DartClusterBodyKind::Array,
            "GrowableObjectArray" => DartClusterBodyKind::GrowableObjectArray,
            "String" => DartClusterBodyKind::String,
            "Instance" | "FfiInt8" | "FfiInt16" | "FfiInt32" | "FfiInt64" | "FfiUint8"
            | "FfiUint16" | "FfiUint32" | "FfiUint64" | "FfiFloat" | "FfiDouble" | "FfiVoid"
            | "FfiHandle" | "FfiBool" => DartClusterBodyKind::Instance,
            _ => return None,
        };
        Some(kind)
    }

    pub(super) fn typed_data_element_size(self, class_id: u32) -> Option<usize> {
        let cid: u16 = u16::try_from(class_id).ok()?;
        typed_data_element_bytes(self.class_ids.name(cid)?)
    }
}

fn typed_data_element_bytes(name: &str) -> Option<usize> {
    let element: &str = name.strip_prefix("TypedData")?.strip_suffix("Array")?;
    match element {
        "Int8" | "Uint8" | "Uint8Clamped" => Some(1),
        "Int16" | "Uint16" => Some(2),
        "Int32" | "Uint32" | "Float32" => Some(4),
        "Int64" | "Uint64" | "Float64" => Some(8),
        "Float32x4" | "Int32x4" | "Float64x2" => Some(16),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{
        DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT, DartClusterBodyKind, DartPinnedLayout,
        PINNED_DART_GRAPH_LAYOUTS, has_pinned_dart_graph_layout, pinned_dart_graph_layout,
    };
    use crate::flutter::cid_table::DART_3_12_VERSION_HASH;

    #[test]
    fn maps_only_the_string_cluster_class_id_to_strings() {
        let layout: DartPinnedLayout = DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT;
        assert_eq!(
            layout.cluster_body_kind(93),
            Some(DartClusterBodyKind::String)
        );
        assert_eq!(layout.cluster_body_kind(94), None);
    }

    #[test]
    fn typed_data_clusters_cover_internal_typed_data_only() {
        let layout: DartPinnedLayout = DART_3_12_2_ANDROID_ARM64_PRODUCT_LAYOUT;
        let int8: u32 = layout.class_id("TypedDataInt8Array").expect("int8");
        assert_eq!(
            layout.cluster_body_kind(int8),
            Some(DartClusterBodyKind::TypedData)
        );
        assert_eq!(layout.typed_data_element_size(int8), Some(1));
        assert_eq!(layout.cluster_body_kind(int8 + 1), None);
        assert_eq!(layout.cluster_body_kind(int8 + 2), None);
        let float64x2: u32 = layout
            .class_id("TypedDataFloat64x2Array")
            .expect("float64x2");
        assert_eq!(layout.typed_data_element_size(float64x2), Some(16));
    }

    #[test]
    fn class_ids_above_the_predefined_range_are_instances() {
        for layout in PINNED_DART_GRAPH_LAYOUTS {
            let first_user_class: u32 = u32::from(layout.class_ids.predefined_count());
            assert_eq!(
                layout.cluster_body_kind(first_user_class),
                Some(DartClusterBodyKind::Instance)
            );
            assert_eq!(
                layout.cluster_body_kind(first_user_class - 1),
                None,
                "Never is a pseudo class id and has no cluster"
            );
        }
    }

    #[test]
    fn every_release_pins_a_product_and_a_dwarf_tuple() {
        for layout in PINNED_DART_GRAPH_LAYOUTS {
            let dwarf: String = layout
                .features
                .replace("no-dwarf_stack_traces_mode", "dwarf_stack_traces_mode");
            let product: String = layout
                .features
                .replace(" dwarf_stack_traces_mode", " no-dwarf_stack_traces_mode");
            assert!(pinned_dart_graph_layout(layout.version_hash, &dwarf).is_some());
            assert!(pinned_dart_graph_layout(layout.version_hash, &product).is_some());
        }
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
