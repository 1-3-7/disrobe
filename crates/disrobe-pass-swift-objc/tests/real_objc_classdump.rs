#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{CpuKind, ParsedSlice};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::{ObjcInterface, ObjcMethod};

use macho_corpus::{
    CorpusFixture, SWIFT_DRIVER, macos_system_binary, read_host_sourced, slice_preferring,
};

const CODESIGN: CorpusFixture = macos_system_binary("codesign");

fn x86_64_slice(fixture: CorpusFixture) -> Option<(Vec<u8>, ParsedSlice)> {
    let bytes: Vec<u8> = read_host_sourced(fixture)?;
    Some(slice_preferring(fixture, &bytes, CpuKind::X86_64))
}

#[test]
fn codesign_recovers_real_class_interfaces_with_names() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = x86_64_slice(CODESIGN) else {
        return;
    };
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    assert_eq!(
        dump.class_count, 3,
        "codesign x86_64 should expose exactly 3 ObjC classes"
    );
    assert_eq!(
        dump.interfaces.len(),
        dump.class_count,
        "every classlist pointer must dereference to a recovered @interface, not just a count"
    );

    let names: Vec<&str> = dump
        .interfaces
        .iter()
        .map(|i: &ObjcInterface| i.name.as_str())
        .collect();
    for expected in [
        "_TtC8codesign6CSList",
        "_TtC8codesign18RemoteIdentityInfo",
        "_TtC8codesign14ExtensionUtils",
    ] {
        assert!(
            names.contains(&expected),
            "recovered class names {names:?} missing {expected}"
        );
    }
}

#[test]
fn codesign_interfaces_render_objc_at_interface_blocks() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = x86_64_slice(CODESIGN) else {
        return;
    };
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    let rendered: String = dump
        .interfaces
        .iter()
        .map(ObjcInterface::render)
        .collect::<Vec<String>>()
        .join("\n");
    assert!(
        rendered.contains("@interface _TtC8codesign6CSList"),
        "render must emit an @interface header for a recovered class"
    );
    assert!(
        rendered.matches("@end").count() >= 3,
        "each recovered class must be terminated with @end"
    );
}

#[test]
fn system_binary_recovers_objc_methods_from_method_lists() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = x86_64_slice(CODESIGN) else {
        return;
    };
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    let total_methods: usize = dump
        .interfaces
        .iter()
        .map(|i: &ObjcInterface| i.instance_methods.len() + i.class_methods.len())
        .sum();
    assert!(
        dump.class_count > 0,
        "this case grades method_list_t dereference against the classes {} carries, so a run that \
         recovers zero classes from it has measured nothing and must not report success",
        CODESIGN.relative()
    );
    assert!(
        total_methods > 0,
        "with {} classes present, method_list_t dereference must yield at least one method",
        dump.class_count
    );
    let has_typed_method: bool = dump.interfaces.iter().any(|i: &ObjcInterface| {
        i.instance_methods
            .iter()
            .chain(i.class_methods.iter())
            .any(|m: &ObjcMethod| m.types.is_some() && !m.name.is_empty())
    });
    assert!(
        has_typed_method,
        "at least one recovered method must carry a real selector name and ObjC type encoding"
    );
}

#[test]
fn swift_driver_recovers_dozens_of_class_interfaces() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = x86_64_slice(SWIFT_DRIVER) else {
        return;
    };
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    assert!(
        dump.class_count >= 40,
        "swift-driver should expose 40+ ObjC-visible classes, got {}",
        dump.class_count
    );
    assert!(
        dump.interfaces.len() >= dump.class_count - 2,
        "nearly every class pointer must dereference to a real interface ({} of {})",
        dump.interfaces.len(),
        dump.class_count
    );
    let named: usize = dump
        .interfaces
        .iter()
        .filter(|i: &&ObjcInterface| i.name.contains("SwiftDriver"))
        .count();
    assert!(
        named >= 10,
        "expected many SwiftDriver.* class names among recovered interfaces, got {named}"
    );
}
