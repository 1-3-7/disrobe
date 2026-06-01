#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, CpuKind, FatArchEntry, MachoKind, ParsedSlice};
use disrobe_pass_swift_objc::objc::{self, ObjcClassDump};
use disrobe_pass_swift_objc::objc_records::{ObjcInterface, ObjcMethod};

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
    let path: PathBuf = corpus_root().join(name);
    fs::read(&path).ok()
}

fn first_x86_64_slice(bytes: &[u8]) -> (Vec<u8>, ParsedSlice) {
    let kind: MachoKind = macho::detect_magic(bytes).expect("mach-o magic");
    match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => {
            let entries: Vec<FatArchEntry> = macho::walk_fat(bytes).expect("walk fat");
            let entry: &FatArchEntry = entries
                .iter()
                .find(|e: &&FatArchEntry| matches!(e.cpu, CpuKind::X86_64))
                .or_else(|| entries.first())
                .expect("at least one slice");
            let inner: &[u8] = macho::slice_bytes(bytes, entry).expect("slice bytes");
            let parsed: ParsedSlice = macho::parse_slice(inner).expect("parse slice");
            (inner.to_vec(), parsed)
        }
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(bytes).expect("parse thin slice");
            (bytes.to_vec(), parsed)
        }
    }
}

#[test]
fn codesign_recovers_real_class_interfaces_with_names() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("codesign") else {
        eprintln!("skip: macho-mac/codesign fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
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
    let Some(bytes): Option<Vec<u8>> = load_fixture("codesign") else {
        eprintln!("skip: macho-mac/codesign fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
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
fn ls_system_binary_recovers_objc_methods_from_method_lists() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("ls") else {
        eprintln!("skip: macho-mac/ls fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
    let dump: ObjcClassDump = objc::class_dump(&slice, &parsed);

    let total_methods: usize = dump
        .interfaces
        .iter()
        .map(|i: &ObjcInterface| i.instance_methods.len() + i.class_methods.len())
        .sum();
    if dump.class_count == 0 {
        return;
    }
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
    let Some(bytes): Option<Vec<u8>> = load_fixture("swift-driver") else {
        eprintln!("skip: macho-mac/swift-driver fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
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
