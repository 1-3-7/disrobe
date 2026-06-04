#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, MachoKind, ParsedSlice};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::{ObjcInterface, ObjcIvar};
use disrobe_pass_swift_objc::pass::{self, SliceReport, SwiftObjcReport};

fn corpus_root() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mobile")
        .join("macho-mac")
}

fn load_fixture(name: &str) -> Option<Vec<u8>> {
    fs::read(corpus_root().join(name)).ok()
}

fn thin_slice(bytes: &[u8]) -> (Vec<u8>, ParsedSlice) {
    match macho::detect_magic(bytes).expect("mach-o magic") {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<macho::FatArchEntry> = macho::walk_fat(bytes).expect("walk fat");
            let entry: &macho::FatArchEntry = entries.first().expect("a slice");
            let inner: &[u8] = macho::slice_bytes(bytes, entry).expect("slice bytes");
            let parsed: ParsedSlice = macho::parse_slice(inner).expect("parse slice");
            (inner.to_vec(), parsed)
        }
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(bytes).expect("parse thin");
            (bytes.to_vec(), parsed)
        }
    }
}

#[test]
fn swifthello_recovers_objc_class_interfaces_with_names_and_ivars() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent (LEGAL.md sourcing-gated)");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes);
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
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes);
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
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
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
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.obfuscated") else {
        eprintln!("skip: macho-mac/SwiftHello.obfuscated fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = thin_slice(&bytes);
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
