use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const RESOURCE_CLASS_NAMES: &[&str] = &[
    "Animation",
    "BuildColumn",
    "BuildRow",
    "BuildTable",
    "Character",
    "Cloth",
    "CollisionMaterial",
    "CompiledFutureResolutionTextureMap",
    "CompiledHighResolutionTextureMap",
    "CompiledLowResolutionGuiTextureMap",
    "CompiledLowResolutionTextureMap",
    "CompiledMediumResolutionGuiTextureMap",
    "CompiledMediumResolutionTextureMap",
    "CompiledMesh",
    "CompiledMeshObject",
    "CompiledMeshShapeDataObject",
    "CompiledSoundBank",
    "CompiledSoundMedia",
    "CompiledTextureMap",
    "CompiledTextureMapData",
    "CompiledUltraResolutionTextureMap",
    "CompressedLocalizationData",
    "DepGraph",
    "Entity",
    "EntityBuilder",
    "EntityGroup",
    "FX",
    "FacialSolverData",
    "FastLoadTableOfContents",
    "GIStream",
    "Gadget",
    "GameBootstrap",
    "GlobalMetaFile",
    "LoadUnit",
    "LocalizationPackage",
    "LocalizedString",
    "Material",
    "MaterialTemplate",
    "Mesh",
    "PlatformManager",
    "PrefetchingFileInfos",
    "RowSelection",
    "RowSelector",
    "ShaderCodeModuleUserMaterial",
    "Skeleton",
    "SoftBody",
    "TextureMap",
    "TextureMapSpec",
    "TextureSet",
    "Weapon",
    "WeaponData",
    "World",
    "WorldMetaData",
];

pub const STATIC_UIDS: &[(u64, &str)] = &[
    (0x010, "DataControlGlobalMetaKey"),
    (0x800, "GameBootstrap"),
    (0x80A, "UIFactory"),
    (0x816, "GameSettings"),
    (0x833, "GameSoundSettings"),
    (0x83B, "Universe"),
    (0xBE0, "FastLoadTableOfContents"),
];

pub const DESCRIPTOR_UID: u64 = 0x10;
pub const FAST_LOAD_TOC_UID: u64 = 0xBE0;

#[must_use]
pub fn type_id(class_name: &str) -> u32 {
    crc32fast::hash(class_name.as_bytes())
}

fn id_table() -> &'static BTreeMap<u32, &'static str> {
    static TABLE: OnceLock<BTreeMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        RESOURCE_CLASS_NAMES
            .iter()
            .map(|name: &&'static str| (type_id(name), *name))
            .collect()
    })
}

#[must_use]
pub fn type_name(id: u32) -> Option<&'static str> {
    id_table().get(&id).copied()
}

#[must_use]
pub fn type_label(id: u32) -> String {
    type_name(id).map_or_else(|| format!("0x{id:08X}"), str::to_owned)
}

#[must_use]
pub fn static_uid_name(uid: u64) -> Option<&'static str> {
    STATIC_UIDS
        .iter()
        .find(|(known, _): &&(u64, &str)| *known == uid)
        .map(|(_, name): &(u64, &str)| *name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const REFERENCE_IDS: &[(&str, u32)] = &[
        ("CompiledMeshObject", 0xABEB_2DFB),
        ("CompiledMesh", 0xFC9E_1595),
        ("CompiledTextureMap", 0x1323_7FE9),
        ("CompiledLowResolutionTextureMap", 0xD7B5_C478),
        ("CompiledSoundMedia", 0x4274_11A3),
        ("Material", 0x85C8_17C3),
        ("TextureMapSpec", 0x989D_C6B2),
        ("TextureMap", 0xA2B7_E917),
        ("Mesh", 0x415D_9568),
        ("Skeleton", 0x24AE_CB7C),
        ("Entity", 0x0984_415E),
        ("World", 0xFBB6_3E47),
        ("LoadUnit", 0x9439_45C4),
        ("CompiledSoundBank", 0x8268_8E42),
        ("BuildTable", 0x22EC_BE63),
        ("EntityBuilder", 0x971A_842E),
        ("GameBootstrap", 0xE5A8_3560),
        ("LocalizationPackage", 0x6E3C_9C6F),
        ("Cloth", 0xE330_44BA),
        ("FastLoadTableOfContents", 0xA7C6_8C14),
        ("CompiledTextureMapData", 0xC30C_4B3D),
    ];

    #[test]
    fn type_ids_match_the_published_crc32_values() {
        for (name, expected) in REFERENCE_IDS {
            assert_eq!(type_id(name), *expected, "{name}");
            assert_eq!(type_name(*expected), Some(*name));
            assert_eq!(type_label(*expected), *name);
        }
    }

    #[test]
    fn a_changed_class_name_changes_the_id() {
        assert_ne!(
            type_id("CompiledMeshObject"),
            type_id("CompiledMeshObjects")
        );
        assert_ne!(type_id("compiledmeshobject"), 0xABEB_2DFB);
    }

    #[test]
    fn unknown_ids_are_labelled_in_hex_and_no_two_names_collide() {
        assert_eq!(type_label(0x0000_0001), "0x00000001");
        assert_eq!(type_name(0), None);
        assert_eq!(id_table().len(), RESOURCE_CLASS_NAMES.len());
        let mut sorted: Vec<&str> = RESOURCE_CLASS_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), RESOURCE_CLASS_NAMES.len());
    }

    #[test]
    fn static_uids_resolve() {
        assert_eq!(
            static_uid_name(DESCRIPTOR_UID),
            Some("DataControlGlobalMetaKey")
        );
        assert_eq!(
            static_uid_name(FAST_LOAD_TOC_UID),
            Some("FastLoadTableOfContents")
        );
        assert_eq!(static_uid_name(0x12345), None);
    }
}
