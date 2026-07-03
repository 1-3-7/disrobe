#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_swift_objc::macho::{self, CpuKind, FatArchEntry, MachoKind, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
use disrobe_pass_swift_objc::swift_reflect::{SwiftField, SwiftTypeReflection};

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
fn swift_driver_recovers_structured_field_names_per_type() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("swift-driver") else {
        eprintln!("skip: macho-mac/swift-driver fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    assert!(
        dump.reflected_types.len() >= 50,
        "swift-driver __swift5_fieldmd should yield 50+ structured reflected types, got {}",
        dump.reflected_types.len()
    );

    let total_fields: usize = dump
        .reflected_types
        .iter()
        .map(|t: &SwiftTypeReflection| t.fields.len())
        .sum();
    assert!(
        total_fields >= 100,
        "expected 100+ structurally associated field records, got {total_fields}"
    );

    let all_field_names: Vec<&str> = dump
        .reflected_types
        .iter()
        .flat_map(|t: &SwiftTypeReflection| t.fields.iter())
        .map(|f: &SwiftField| f.name.as_str())
        .collect();
    for expected in ["spelling", "kind", "metaVar", "rawValue"] {
        assert!(
            all_field_names.contains(&expected),
            "structured field-name recovery missing {expected}"
        );
    }
}

#[test]
fn swift_driver_demangles_standard_library_field_types() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("swift-driver") else {
        eprintln!("skip: macho-mac/swift-driver fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let demangled_types: Vec<&str> = dump
        .reflected_types
        .iter()
        .flat_map(|t: &SwiftTypeReflection| t.fields.iter())
        .filter_map(|f: &SwiftField| f.demangled_type.as_deref())
        .collect();

    let saw_string: bool = demangled_types
        .iter()
        .any(|t: &&str| t.contains("Swift.String"));
    let saw_int_or_uint: bool = demangled_types
        .iter()
        .any(|t: &&str| t.contains("Swift.Int") || t.contains("Swift.UInt"));
    assert!(
        saw_string,
        "expected at least one field demangled to Swift.String among {} demangled types",
        demangled_types.len()
    );
    assert!(
        saw_int_or_uint,
        "expected at least one field demangled to Swift.Int/UInt"
    );
}

#[test]
fn swift_driver_renders_swift_type_declarations() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("swift-driver") else {
        eprintln!("skip: macho-mac/swift-driver fixture absent");
        return;
    };
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_x86_64_slice(&bytes);
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);

    let rendered: String = dump
        .reflected_types
        .iter()
        .map(SwiftTypeReflection::render)
        .collect::<Vec<String>>()
        .join("\n");
    let has_decl: bool =
        rendered.contains("struct ") || rendered.contains("class ") || rendered.contains("enum ");
    assert!(
        has_decl,
        "render must emit at least one Swift type declaration"
    );
    assert!(
        rendered.contains("spelling"),
        "rendered reflection must contain a recovered field name"
    );
}

#[test]
fn swift_hello_original_recovers_named_types() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("SwiftHello.original") else {
        eprintln!("skip: macho-mac/SwiftHello.original fixture absent");
        return;
    };
    let kind: MachoKind = macho::detect_magic(&bytes).expect("magic");
    let (slice, parsed): (Vec<u8>, ParsedSlice) = match kind {
        MachoKind::Fat32 | MachoKind::Fat64 => first_x86_64_slice(&bytes),
        _ => {
            let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse");
            (bytes, parsed)
        }
    };
    let dump: SwiftClassDump = swift::class_dump(&slice, &parsed);
    assert!(
        !dump.reflected_types.is_empty(),
        "SwiftHello.original must yield at least one reflected Swift type"
    );
    let has_named: bool = dump
        .reflected_types
        .iter()
        .any(|t: &SwiftTypeReflection| !t.fields.is_empty());
    assert!(
        has_named,
        "SwiftHello.original reflected types must carry at least one field record"
    );
}
