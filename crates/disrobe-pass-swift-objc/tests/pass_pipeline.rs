#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::pass::{ContainerKind, SwiftObjcReport, analyze};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_binary_info_plist,
    build_ipa_with_main_binary, build_macho64_slice, build_objc_classlist_payload,
    build_objc_methname_payload, build_swift_reflstr_payload,
};

fn rich_slice() -> Vec<u8> {
    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![
            MachoSegmentSpec {
                seg_name: "__TEXT",
                sections: vec![
                    MachoSectionSpec {
                        sect_name: "__swift5_types",
                        seg_name: "__TEXT",
                        data: vec![0u8; 12],
                    },
                    MachoSectionSpec {
                        sect_name: "__swift5_reflstr",
                        seg_name: "__TEXT",
                        data: build_swift_reflstr_payload(&["$s5Hello5WorldC"]),
                    },
                    MachoSectionSpec {
                        sect_name: "__objc_methname",
                        seg_name: "__TEXT",
                        data: build_objc_methname_payload(&["init", "setName:"]),
                    },
                ],
            },
            MachoSegmentSpec {
                seg_name: "__DATA",
                sections: vec![MachoSectionSpec {
                    sect_name: "__objc_classlist",
                    seg_name: "__DATA",
                    data: build_objc_classlist_payload(2),
                }],
            },
        ],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn analyze_recovers_swift_and_objc_metadata_from_a_macho_slice() {
    let slice: Vec<u8> = rich_slice();
    let report: SwiftObjcReport = analyze(&slice).expect("analyze runs");
    assert_eq!(report.container, ContainerKind::MachO);
    assert_eq!(report.slices.len(), 1);
    let slice_report: &disrobe_pass_swift_objc::pass::SliceReport = &report.slices[0];
    assert_eq!(slice_report.bitness_bits, 64);
    assert_eq!(slice_report.cpu_label, "arm64");
    assert!(slice_report.swift.types_section.is_some());
    assert!(slice_report.swift.reflection_strings.is_some());
    assert_eq!(slice_report.objc.class_count, 2);
    assert!(!slice_report.fairplay.is_encrypted);
}

#[test]
fn analyze_extracts_the_main_binary_from_an_ipa_artifact() {
    let main_bin: Vec<u8> = rich_slice();
    let plist: Vec<u8> = build_binary_info_plist();
    let ipa: Vec<u8> = build_ipa_with_main_binary("Example", &main_bin, &plist);
    let report: SwiftObjcReport = analyze(&ipa).expect("analyze runs");
    assert_eq!(report.container, ContainerKind::Ipa);
    assert!(report.ipa.is_some());
    assert_eq!(report.slices.len(), 1);
}
