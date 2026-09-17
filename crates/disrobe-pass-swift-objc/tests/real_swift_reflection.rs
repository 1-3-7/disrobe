#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::{CpuKind, ParsedSlice};
use disrobe_pass_swift_objc::swift::{self, SwiftClassDump};
use disrobe_pass_swift_objc::swift_reflect::{SwiftField, SwiftTypeReflection};

use macho_corpus::{
    SWIFT_DRIVER, SWIFT_HELLO_ORIGINAL, first_slice, read_host_sourced, read_tracked,
    slice_preferring,
};

fn driver_x86_64_slice() -> Option<(Vec<u8>, ParsedSlice)> {
    let bytes: Vec<u8> = read_host_sourced(SWIFT_DRIVER)?;
    Some(slice_preferring(SWIFT_DRIVER, &bytes, CpuKind::X86_64))
}

#[test]
fn swift_driver_recovers_structured_field_names_per_type() {
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_x86_64_slice() else {
        return;
    };
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
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_x86_64_slice() else {
        return;
    };
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
    let Some((slice, parsed)): Option<(Vec<u8>, ParsedSlice)> = driver_x86_64_slice() else {
        return;
    };
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
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
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
