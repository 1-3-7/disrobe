#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump, SelectorIndex};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_macho64_slice,
    build_objc_classlist_payload, build_objc_methname_payload,
};

fn slice_with_objc_sections() -> Vec<u8> {
    let classlist: Vec<u8> = build_objc_classlist_payload(3);
    let methname: Vec<u8> = build_objc_methname_payload(&[
        "init",
        "setName:",
        "name",
        "copyZone",
        "performAction:withSender:",
    ]);
    let classname: Vec<u8> = build_objc_methname_payload(&["LoginViewController", "User"]);

    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![
            MachoSegmentSpec {
                seg_name: "__DATA",
                sections: vec![MachoSectionSpec {
                    sect_name: "__objc_classlist",
                    seg_name: "__DATA",
                    data: classlist,
                }],
            },
            MachoSegmentSpec {
                seg_name: "__TEXT",
                sections: vec![
                    MachoSectionSpec {
                        sect_name: "__objc_methname",
                        seg_name: "__TEXT",
                        data: methname,
                    },
                    MachoSectionSpec {
                        sect_name: "__objc_classname",
                        seg_name: "__TEXT",
                        data: classname,
                    },
                ],
            },
        ],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn objc_classlist_and_methname_are_extracted() {
    let slice: Vec<u8> = slice_with_objc_sections();
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);
    assert_eq!(dump.class_count, 3);
    assert!(dump.unique_selectors.contains("init"));
    assert!(dump.unique_selectors.contains("setName:"));
    assert!(dump.unique_class_names.contains("LoginViewController"));
}

#[test]
fn selector_recovery_classifies_setters_getters_init_copy() {
    let slice: Vec<u8> = slice_with_objc_sections();
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);
    let index: SelectorIndex = objc::index_selectors(&dump);
    assert!(index.setters.contains("setName:"));
    assert!(index.getters.contains("name"));
    assert!(index.init_family.contains("init"));
    assert!(index.copy_family.contains("copyZone"));
}
