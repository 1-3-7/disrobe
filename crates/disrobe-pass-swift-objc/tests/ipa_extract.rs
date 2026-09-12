#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::ipa::{self, IpaExtract, IpaInventory};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_binary_info_plist,
    build_info_plist_with_executable, build_ipa_from_files, build_ipa_with_main_binary,
    build_macho64_slice,
};

fn tiny_main_binary() -> Vec<u8> {
    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![MachoSectionSpec {
                sect_name: "__text",
                seg_name: "__TEXT",
                data: vec![0u8; 32],
            }],
        }],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn ipa_inventory_locates_app_bundle_and_main_binary() {
    let main_bin: Vec<u8> = tiny_main_binary();
    let plist: Vec<u8> = build_binary_info_plist();
    let ipa: Vec<u8> = build_ipa_with_main_binary("Example", &main_bin, &plist);
    let inventory: IpaInventory = ipa::inventory(&ipa).expect("inventory");
    assert_eq!(inventory.app_dir, "Payload/Example.app");
    assert_eq!(inventory.bundle_name, "Example");
    assert_eq!(
        inventory.main_binary_path.as_deref(),
        Some("Payload/Example.app/Example")
    );
    assert_eq!(
        inventory.info_plist_path.as_deref(),
        Some("Payload/Example.app/Info.plist")
    );
}

#[test]
fn ipa_inventory_honors_cfbundleexecutable_over_app_name_heuristic() {
    let expected_binary: Vec<u8> = tiny_main_binary();
    let plist: Vec<u8> = build_info_plist_with_executable("Example", "ExampleBin");
    let files: Vec<(String, Vec<u8>)> = vec![
        (
            "Payload/Example.app/Example".to_owned(),
            b"decoy resource not the executable".to_vec(),
        ),
        (
            "Payload/Example.app/ExampleBin".to_owned(),
            tiny_main_binary(),
        ),
        ("Payload/Example.app/Info.plist".to_owned(), plist),
    ];
    let ipa: Vec<u8> = build_ipa_from_files(&files);
    let inventory: IpaInventory = ipa::inventory(&ipa).expect("inventory");
    assert_eq!(inventory.app_dir, "Payload/Example.app");
    assert_eq!(inventory.bundle_name, "Example");
    assert_eq!(
        inventory.main_binary_path.as_deref(),
        Some("Payload/Example.app/ExampleBin"),
        "main binary must follow CFBundleExecutable, not the .app-name heuristic"
    );

    let extracted: IpaExtract = ipa::extract(&ipa).expect("extract");
    assert_eq!(
        extracted.main_binary.as_deref(),
        Some(expected_binary.as_slice()),
        "extract must return the CFBundleExecutable binary, not the decoy"
    );
}

#[test]
fn ipa_inventory_falls_back_to_app_name_when_executable_absent() {
    let files: Vec<(String, Vec<u8>)> = vec![
        ("Payload/Example.app/Example".to_owned(), tiny_main_binary()),
        (
            "Payload/Example.app/Info.plist".to_owned(),
            b"not a valid plist".to_vec(),
        ),
    ];
    let ipa: Vec<u8> = build_ipa_from_files(&files);
    let inventory: IpaInventory = ipa::inventory(&ipa).expect("inventory");
    assert_eq!(
        inventory.main_binary_path.as_deref(),
        Some("Payload/Example.app/Example"),
        "with no readable CFBundleExecutable the .app-name heuristic must still locate the binary"
    );
}

#[test]
fn ipa_extract_returns_main_binary_and_plist_bytes() {
    let main_bin: Vec<u8> = tiny_main_binary();
    let plist: Vec<u8> = build_binary_info_plist();
    let ipa: Vec<u8> = build_ipa_with_main_binary("Example", &main_bin, &plist);
    let extracted: IpaExtract = ipa::extract(&ipa).expect("extract");
    assert_eq!(extracted.main_binary.as_deref(), Some(main_bin.as_slice()));
    assert_eq!(extracted.info_plist.as_deref(), Some(plist.as_slice()));
}
