#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_macho64_slice,
    build_swift_reflstr_payload,
};

fn slice_with_swift_sections() -> Vec<u8> {
    let types_pointers: Vec<u8> = vec![0u8; 16];
    let protos_pointers: Vec<u8> = vec![0u8; 8];
    let reflstr: Vec<u8> =
        build_swift_reflstr_payload(&["$s5Hello5WorldC", "$s3App4UserV", "_T03foo3barF"]);

    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![
                MachoSectionSpec {
                    sect_name: "__swift5_types",
                    seg_name: "__TEXT",
                    data: types_pointers,
                },
                MachoSectionSpec {
                    sect_name: "__swift5_protos",
                    seg_name: "__TEXT",
                    data: protos_pointers,
                },
                MachoSectionSpec {
                    sect_name: "__swift5_reflstr",
                    seg_name: "__TEXT",
                    data: reflstr,
                },
            ],
        }],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn swift_class_dump_collects_all_sections() {
    let slice: Vec<u8> = slice_with_swift_sections();
    let parsed: ParsedSlice = macho::parse_slice(&slice).expect("parse");
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    let types: &swift::SwiftSectionPointers =
        dump.types_section.as_ref().expect("__swift5_types present");
    assert_eq!(types.pointer_count, 4);
    let protos: &swift::SwiftSectionPointers = dump
        .protos_section
        .as_ref()
        .expect("__swift5_protos present");
    assert_eq!(protos.pointer_count, 2);
    let reflstr: &swift::SwiftReflectionStrings = dump
        .reflection_strings
        .as_ref()
        .expect("__swift5_reflstr present");
    assert_eq!(reflstr.strings.len(), 3);
    assert!(
        dump.mangled_symbols
            .iter()
            .any(|s: &String| s == "$s5Hello5WorldC")
    );
    let demangled_hello: &String = dump
        .demangled
        .get("$s5Hello5WorldC")
        .expect("demangled present");
    assert_eq!(demangled_hello, "Hello.World (class)");
}

#[test]
fn swift_demangle_handles_class_and_struct_kinds() {
    let class: String = swift::demangle("$s5Hello5WorldC").expect("class");
    assert_eq!(class, "Hello.World (class)");
    let strukt: String = swift::demangle("$s3App4UserV").expect("struct");
    assert_eq!(strukt, "App.User (struct)");
}

#[test]
fn confidential_decrypt_xor_roundtrip() {
    let secret: &[u8] = b"flag{example}\0";
    let key: u8 = 0xA5;
    let encrypted: Vec<u8> = swift::confidential_xor_decrypt(secret, key);
    let recovered: swift::ConfidentialDecryptResult =
        swift::confidential_recover_strings(&encrypted, key);
    assert_eq!(recovered.recovered, vec!["flag{example}".to_owned()]);
    assert_eq!(recovered.key, key);
}

#[test]
fn swiftshield_undo_recovers_mapping_from_dsym_text() {
    let text: &str = "a8X9k2 ==> LoginViewController\nz7q3w1 ==> AuthService\n";
    let map: swift::SwiftShieldUndoMap = swift::swiftshield_undo_from_dsym_text(text);
    assert_eq!(map.mappings.len(), 2);
}
