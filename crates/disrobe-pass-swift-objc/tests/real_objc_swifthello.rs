#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::ParsedSlice;
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::{ObjcInterface, ObjcIvar};
use disrobe_pass_swift_objc::pass::{self, SliceReport, SwiftObjcReport};

use macho_corpus::{
    CorpusFixture, SWIFT_HELLO_OBFUSCATED, SWIFT_HELLO_ORIGINAL, first_slice, read_tracked,
};

fn tracked_slice(fixture: CorpusFixture) -> (Vec<u8>, ParsedSlice) {
    let bytes: Vec<u8> = read_tracked(fixture);
    first_slice(fixture, &bytes)
}

#[test]
fn swifthello_recovers_objc_class_interfaces_with_names_and_ivars() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    assert!(
        dump.class_count >= 2,
        "SwiftHello exposes >=2 ObjC-visible classes, got {}",
        dump.class_count
    );
    assert_eq!(
        dump.interfaces.len(),
        dump.class_count,
        "every classlist pointer must dereference to a recovered @interface"
    );

    let names: Vec<&str> = dump
        .interfaces
        .iter()
        .map(|i: &ObjcInterface| i.name.as_str())
        .collect();
    for expected in [
        "_TtC10SwiftHello19LoginViewController",
        "_TtC10SwiftHello21AuthenticationService",
    ] {
        assert!(
            names.contains(&expected),
            "recovered class names {names:?} missing {expected}"
        );
    }

    let ivar_names: Vec<&str> = dump
        .interfaces
        .iter()
        .flat_map(|i: &ObjcInterface| i.ivars.iter())
        .map(|v: &ObjcIvar| v.name.as_str())
        .collect();
    for expected in ["displayedUserName", "configuredEndpointPath"] {
        assert!(
            ivar_names.contains(&expected),
            "recovered ivars {ivar_names:?} missing {expected}"
        );
    }
}

#[test]
fn swifthello_classname_and_methname_string_tables_are_present() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_ORIGINAL);
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    assert!(
        dump.class_names.is_some(),
        "__objc_classname C-string table must parse"
    );
    assert!(
        dump.unique_class_names
            .iter()
            .any(|n: &String| n.contains("LoginViewController")),
        "class-name string table must hold the ground-truth class identifier"
    );
}

#[test]
fn swifthello_pass_report_metadata_summary_reflects_recovery() {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let report: SwiftObjcReport = pass::analyze(&bytes).expect("analyze");
    let slice: &SliceReport = report.slices.first().expect("a slice report");
    let s: &pass::MetadataSummary = &slice.metadata_summary;

    assert!(
        s.objc_classes >= 2 && s.objc_interfaces_recovered == s.objc_classes,
        "summary must count recovered ObjC interfaces: {s:?}"
    );
    assert!(
        s.swift_reflected_types >= 1,
        "summary must count reflected Swift types: {s:?}"
    );
    assert!(
        s.swift_demangled_symbols >= 1 && s.swift_demangled_symbols <= s.swift_mangled_symbols,
        "summary must count demangled symbols within the mangled set: {s:?}"
    );
}

#[test]
fn swifthello_obfuscated_objc_metadata_still_structurally_recovers() {
    let (slice, parsed): (Vec<u8>, ParsedSlice) = tracked_slice(SWIFT_HELLO_OBFUSCATED);
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    assert!(
        dump.class_count >= 2,
        "obfuscated binary still exposes >=2 ObjC classes, got {}",
        dump.class_count
    );
    assert_eq!(dump.interfaces.len(), dump.class_count);
    let total_ivars: usize = dump
        .interfaces
        .iter()
        .map(|i: &ObjcInterface| i.ivars.len())
        .sum();
    assert!(
        total_ivars >= 2,
        "obfuscated class_ro_t walk must still recover ivar slots, got {total_ivars}"
    );
}
