#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::pass::{ContainerKind, SwiftObjcReport, analyze};
use disrobe_pass_swift_objc::swift_reflect::{SwiftField, SwiftTypeReflection};

use crate::fixtures::{
    MachoSectionSpec, MachoSegmentSpec, MachoSliceBuilder, build_info_plist_with_executable,
    build_ipa_from_files, build_macho64_slice,
};

const CREDENTIALS_INTERFACE: &str = "// swift-interface-format-version: 1.0\n\
// swift-module-flags: -target arm64-apple-ios15.0 -module-name SwiftHello\n\
import Swift\n\
public struct Credentials : Swift.Equatable {\n\
  public let user: Swift.String\n\
  public let secret: Swift.String\n\
}\n";

fn credentials_fieldmd_slice() -> Vec<u8> {
    let mut descriptor: Vec<u8> = Vec::with_capacity(28);
    descriptor.extend_from_slice(&28i32.to_le_bytes());
    descriptor.extend_from_slice(&0i32.to_le_bytes());
    descriptor.extend_from_slice(&0u32.to_le_bytes());
    descriptor.extend_from_slice(&1u32.to_le_bytes());
    descriptor.extend_from_slice(&0u32.to_le_bytes());
    descriptor.extend_from_slice(&0i32.to_le_bytes());
    descriptor.extend_from_slice(&0i32.to_le_bytes());
    assert_eq!(descriptor.len(), 28);

    let mut mangled_name: Vec<u8> = Vec::new();
    mangled_name.extend_from_slice(b"10SwiftHello11CredentialsV");
    mangled_name.push(0);

    let builder: MachoSliceBuilder = MachoSliceBuilder {
        segments: vec![MachoSegmentSpec {
            seg_name: "__TEXT",
            sections: vec![
                MachoSectionSpec {
                    sect_name: "__swift5_fieldmd",
                    seg_name: "__TEXT",
                    data: descriptor,
                },
                MachoSectionSpec {
                    sect_name: "__swift5_reflstr",
                    seg_name: "__TEXT",
                    data: mangled_name,
                },
            ],
        }],
        encryption_id: 0,
    };
    build_macho64_slice(&builder)
}

#[test]
fn analyze_ipa_recovers_elided_field_names_from_bundled_swiftinterface() {
    let main_bin: Vec<u8> = credentials_fieldmd_slice();
    let plist: Vec<u8> = build_info_plist_with_executable("Example", "Example");
    let files: Vec<(String, Vec<u8>)> = vec![
        ("Payload/Example.app/Example".to_owned(), main_bin),
        ("Payload/Example.app/Info.plist".to_owned(), plist),
        (
            "Payload/Example.app/SwiftHello.swiftinterface".to_owned(),
            CREDENTIALS_INTERFACE.as_bytes().to_vec(),
        ),
    ];
    let ipa: Vec<u8> = build_ipa_from_files(&files);

    let report: SwiftObjcReport = analyze(&ipa).expect("analyze runs");
    assert_eq!(report.container, ContainerKind::Ipa);
    assert_eq!(report.slices.len(), 1, "one slice expected");

    let credentials: &SwiftTypeReflection = report.slices[0]
        .swift
        .reflected_types
        .iter()
        .find(|t: &&SwiftTypeReflection| {
            t.demangled_type_name.as_deref() == Some("SwiftHello.Credentials")
        })
        .expect("Credentials reflection recovered from __swift5_fieldmd");

    let names: Vec<&str> = credentials
        .fields
        .iter()
        .map(|f: &SwiftField| f.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["user", "secret"],
        "field names elided from reflection must be filled from the bundled .swiftinterface"
    );
}

#[test]
fn analyze_ipa_without_swiftinterface_leaves_reflection_unnamed() {
    let main_bin: Vec<u8> = credentials_fieldmd_slice();
    let plist: Vec<u8> = build_info_plist_with_executable("Example", "Example");
    let files: Vec<(String, Vec<u8>)> = vec![
        ("Payload/Example.app/Example".to_owned(), main_bin),
        ("Payload/Example.app/Info.plist".to_owned(), plist),
    ];
    let ipa: Vec<u8> = build_ipa_from_files(&files);

    let report: SwiftObjcReport = analyze(&ipa).expect("analyze runs");
    let credentials: &SwiftTypeReflection = report.slices[0]
        .swift
        .reflected_types
        .iter()
        .find(|t: &&SwiftTypeReflection| {
            t.demangled_type_name.as_deref() == Some("SwiftHello.Credentials")
        })
        .expect("Credentials reflection recovered");
    assert!(
        credentials.fields.is_empty(),
        "with no companion interface the elided names stay absent, not fabricated"
    );
}
